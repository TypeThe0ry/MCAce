[CmdletBinding()]
param(
    [switch]$Execute,
    [switch]$ReportOnly,
    [switch]$Resume,
    [ValidateRange(1, 10080)]
    [int]$MaximumReportAgeMinutes = 1440
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$reportSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V1'
$bindingSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_BINDING_V1'
$commitSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_COMMIT_V1'
$preparedTreeDomain = "MCACE_PREPARED_TREE_SHA256_V1`0"
$preparedRoots = @('cache', 'libraries', 'versions')
$targetVersions = @('1.21.11', '26.1.2', '26.2')

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$wrapperPath = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$wrapperTestPath = Join-Path $repoRoot 'scripts\test-server-version-process-matrix.ps1'
$assetRoot = Join-Path $repoRoot 'build\runtime-assets'
$assetManifestPath = Join-Path $assetRoot 'manifest.json'
$preparedManifestPath = Join-Path $assetRoot 'prepared-manifest.json'
$rawRunsRoot = Join-Path $repoRoot 'build\runtime-player-probe\runs'
$workRoot = Join-Path $repoRoot 'build\server-version-process-matrix'
$invocationRoot = Join-Path $workRoot 'invocations'
$evidenceRunsRoot = Join-Path $workRoot 'runs'
$lockPath = Join-Path $workRoot 'matrix.lock'
$checkpointPath = Join-Path $workRoot 'checkpoint.json'
$checkpointSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_CHECKPOINT_V1'

$productJarRelatives = [ordered]@{
    velocity = 'mcace-server-velocity/build/libs/mcace-server-velocity-0.1.0-SNAPSHOT.jar'
    bungee = 'mcace-server-bungeecord/build/libs/mcace-server-bungeecord-0.1.0-SNAPSHOT.jar'
    paper = 'mcace-server-paper/build/libs/mcace-server-paper-0.1.0-SNAPSHOT.jar'
}

# These are reviewed release inputs, not a "latest" lookup and not a fallback list.
$expectedAssets = @(
    [ordered]@{ project='paper'; version='1.21.11'; build='132'; sha256='5ffef465eeeb5f2a3c23a24419d97c51afd7dbb4923ff42df9a3f58bba1ccfba'; size=54846016L; channel='STABLE'; java_major=21; url='https://fill-data.papermc.io/v1/objects/5ffef465eeeb5f2a3c23a24419d97c51afd7dbb4923ff42df9a3f58bba1ccfba/paper-1.21.11-132.jar' },
    [ordered]@{ project='paper'; version='26.1.2'; build='74'; sha256='1d70b1dab9cf4a6de615209a536f3a45a2186240253c428213ce2188ab95e5f7'; size=52893229L; channel='STABLE'; java_major=25; url='https://fill-data.papermc.io/v1/objects/1d70b1dab9cf4a6de615209a536f3a45a2186240253c428213ce2188ab95e5f7/paper-26.1.2-74.jar' },
    [ordered]@{ project='paper'; version='26.2'; build='116'; sha256='17eee738bc0f6b747646be4199672c4efcb2084efd7e291ec5254a45d5ae6f2e'; size=64426830L; channel='STABLE'; java_major=25; url='https://fill-data.papermc.io/v1/objects/17eee738bc0f6b747646be4199672c4efcb2084efd7e291ec5254a45d5ae6f2e/paper-26.2-116.jar' },
    [ordered]@{ project='folia'; version='1.21.11'; build='14'; sha256='f52c408490a0225611e67907a3ca19f7e6da2c6bc899e715d5f46844e7103c39'; size=55082693L; channel='STABLE'; java_major=21; url='https://fill-data.papermc.io/v1/objects/f52c408490a0225611e67907a3ca19f7e6da2c6bc899e715d5f46844e7103c39/folia-1.21.11-14.jar' },
    [ordered]@{ project='folia'; version='26.1.2'; build='8'; sha256='607afd1c3320008e1ffd2eaee6780ace4419d5f8c527b75e79f259be79ebf57b'; size=53184326L; channel='STABLE'; java_major=25; url='https://fill-data.papermc.io/v1/objects/607afd1c3320008e1ffd2eaee6780ace4419d5f8c527b75e79f259be79ebf57b/folia-26.1.2-8.jar' },
    [ordered]@{ project='folia'; version='26.2'; build='6'; sha256='9a728381da3a3bea6732ee210519f8f6ab7d6affe132a430ee167c44c4603d08'; size=64694365L; channel='BETA'; java_major=25; url='https://fill-data.papermc.io/v1/objects/9a728381da3a3bea6732ee210519f8f6ab7d6affe132a430ee167c44c4603d08/folia-26.2-6.jar' },
    [ordered]@{ project='velocity'; version='3.5.1-615'; build='615'; sha256='b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3'; size=18932366L; channel='REVIEWED'; java_major=21; url='https://fill-data.papermc.io/v1/objects/b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3/velocity-3.5.1-615.jar' },
    [ordered]@{ project='bungeecord'; version='2085'; build='2085'; sha256='e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce'; size=25599274L; channel='REVIEWED'; java_major=21; url='https://hub.spigotmc.org/jenkins/job/BungeeCord/2085/artifact/bootstrap/target/BungeeCord.jar' }
)

function ConvertTo-LowerHex([byte[]]$Bytes) {
    return ([BitConverter]::ToString($Bytes)).Replace('-', '').ToLowerInvariant()
}

function Get-BytesSha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ConvertTo-LowerHex ($sha.ComputeHash($Bytes)) }
    finally { $sha.Dispose() }
}

function Get-Int32BigEndianBytes([int]$Value) {
    return [byte[]]@(
        (($Value -shr 24) -band 0xff), (($Value -shr 16) -band 0xff),
        (($Value -shr 8) -band 0xff), ($Value -band 0xff))
}

function Get-Int64BigEndianBytes([long]$Value) {
    return [byte[]]@(
        (($Value -shr 56) -band 0xff), (($Value -shr 48) -band 0xff),
        (($Value -shr 40) -band 0xff), (($Value -shr 32) -band 0xff),
        (($Value -shr 24) -band 0xff), (($Value -shr 16) -band 0xff),
        (($Value -shr 8) -band 0xff), ($Value -band 0xff))
}

function Add-DigestBytes([Security.Cryptography.HashAlgorithm]$Digest, [byte[]]$Bytes) {
    if ($Bytes.Length -gt 0) {
        [void]$Digest.TransformBlock($Bytes, 0, $Bytes.Length, $Bytes, 0)
    }
}

function Assert-DirectLocalPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Directory
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($Directory -and -not $item.PSIsContainer) {
        throw "SERVER_VERSION_MATRIX_DIRECTORY_REQUIRED|$Path"
    }
    if (-not $Directory -and $item.PSIsContainer) {
        throw "SERVER_VERSION_MATRIX_FILE_REQUIRED|$Path"
    }
    if ($null -ne $item.PSDrive -and
            ($item.PSDrive.DisplayRoot -or [string]$item.PSDrive.Root -match '^\\\\')) {
        throw "SERVER_VERSION_MATRIX_LOCAL_DRIVE_REQUIRED|$Path"
    }
    $cursorPath = [IO.Path]::GetFullPath($item.FullName)
    while (-not [string]::IsNullOrWhiteSpace($cursorPath)) {
        $cursor = Get-Item -LiteralPath $cursorPath -Force -ErrorAction Stop
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "SERVER_VERSION_MATRIX_REPARSE_PATH_REJECTED|$($cursor.FullName)"
        }
        $parent = Split-Path -Path $cursorPath -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursorPath) { break }
        $cursorPath = $parent
    }
    return [IO.Path]::GetFullPath($item.FullName)
}

function Assert-ExistingOrParentDirect([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while (-not (Test-Path -LiteralPath $cursor)) {
        $parent = Split-Path -Path $cursor -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) {
            throw "SERVER_VERSION_MATRIX_PATH_PARENT_MISSING|$Path"
        }
        $cursor = $parent
    }
    return Assert-DirectLocalPath $cursor -Directory
}

function Assert-PathBelow([string]$Root, [string]$Path, [string]$Label) {
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([char[]]@('\','/')) + [IO.Path]::DirectorySeparatorChar
    $pathFull = [IO.Path]::GetFullPath($Path)
    $comparison = if ([IO.Path]::DirectorySeparatorChar -eq '\') {
        [StringComparison]::OrdinalIgnoreCase
    } else { [StringComparison]::Ordinal }
    if (-not $pathFull.StartsWith($rootFull, $comparison)) {
        throw "SERVER_VERSION_MATRIX_PATH_ESCAPE|$Label"
    }
    return $pathFull
}

function Get-StableFileDigest([string]$Path) {
    $resolved = Assert-DirectLocalPath $Path
    $before = Get-Item -LiteralPath $resolved -Force
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::Open($resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $hash = ConvertTo-LowerHex ($sha.ComputeHash($stream))
    } finally {
        $stream.Dispose()
        $sha.Dispose()
    }
    $after = Get-Item -LiteralPath $resolved -Force
    if ([long]$before.Length -ne [long]$after.Length -or
            $before.LastWriteTimeUtc -ne $after.LastWriteTimeUtc) {
        throw "SERVER_VERSION_MATRIX_FILE_CHANGED_DURING_HASH|$resolved"
    }
    return [pscustomobject][ordered]@{
        path = $resolved
        sha256 = $hash
        size = [long]$after.Length
        last_write_utc = ([DateTimeOffset]$after.LastWriteTimeUtc).ToUniversalTime()
    }
}

function Test-ExactProperties([object]$Value, [string[]]$Names) {
    if ($null -eq $Value) { return $false }
    $actual = [string[]]@($Value.PSObject.Properties | ForEach-Object Name)
    $expected = [string[]]@($Names)
    [Array]::Sort($actual, [StringComparer]::Ordinal)
    [Array]::Sort($expected, [StringComparer]::Ordinal)
    return $actual.Count -eq $expected.Count -and
        (($actual -join "`n") -ceq ($expected -join "`n"))
}

function Read-StableJson([string]$Path) {
    $resolved = Assert-DirectLocalPath $Path
    $before = Get-Item -LiteralPath $resolved -Force
    $stream = [IO.File]::Open($resolved, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -gt 16777216) {
            throw "SERVER_VERSION_MATRIX_JSON_TOO_LARGE|$Path"
        }
        $memory = [IO.MemoryStream]::new()
        try {
            $stream.CopyTo($memory)
            $bytes = $memory.ToArray()
        } finally { $memory.Dispose() }
    } finally { $stream.Dispose() }
    $after = Get-Item -LiteralPath $resolved -Force
    if ([long]$before.Length -ne [long]$after.Length -or
            $before.LastWriteTimeUtc -ne $after.LastWriteTimeUtc -or
            [long]$after.Length -ne [long]$bytes.Length) {
        throw "SERVER_VERSION_MATRIX_JSON_CHANGED_DURING_READ|$Path"
    }
    $hash = Get-BytesSha256 $bytes
    $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    try { $value = $raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "SERVER_VERSION_MATRIX_JSON_INVALID|$Path" }
    $digest = [pscustomobject]@{
        path = $resolved
        sha256 = $hash
        size = [long]$after.Length
        last_write_utc = ([DateTimeOffset]$after.LastWriteTimeUtc).ToUniversalTime()
    }
    return [pscustomobject]@{ value=$value; raw=$raw; bytes=$bytes; digest=$digest }
}

function Assert-CanonicalRelative([string]$Relative, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Relative) -or
            $Relative.IndexOf('\') -ge 0 -or $Relative.StartsWith('/') -or
            $Relative -match '^[A-Za-z]:' -or $Relative -match '(^|/)\.{1,2}($|/)' -or
            $Relative.IndexOf('//') -ge 0 -or $Relative -cne $Relative.Normalize()) {
        throw "SERVER_VERSION_MATRIX_RELATIVE_INVALID|$Label"
    }
}

function Get-PreparedTreeSnapshot([string]$PreparedRoot) {
    $root = Assert-DirectLocalPath $PreparedRoot -Directory
    $rootPrefix = $root.TrimEnd([char[]]@('\','/')) + [IO.Path]::DirectorySeparatorChar
    $comparison = if ([IO.Path]::DirectorySeparatorChar -eq '\') {
        [StringComparison]::OrdinalIgnoreCase
    } else { [StringComparison]::Ordinal }
    $records = [Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::Ordinal)
    $caseFolded = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($preparedRootName in $preparedRoots) {
        $treeRoot = Assert-DirectLocalPath (Join-Path $root $preparedRootName) -Directory
        foreach ($item in @(Get-ChildItem -LiteralPath $treeRoot -Recurse -Force -ErrorAction Stop)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "SERVER_VERSION_MATRIX_PREPARED_REPARSE|$preparedRootName/$($item.Name)"
            }
            if ($item.PSIsContainer) { continue }
            if (-not ($item -is [IO.FileInfo])) {
                throw "SERVER_VERSION_MATRIX_PREPARED_ENTRY_INVALID|$preparedRootName/$($item.Name)"
            }
            $full = [IO.Path]::GetFullPath($item.FullName)
            if (-not $full.StartsWith($rootPrefix, $comparison)) {
                throw "SERVER_VERSION_MATRIX_PREPARED_ESCAPE|$preparedRootName/$($item.Name)"
            }
            $relative = $full.Substring($rootPrefix.Length).Replace('\','/')
            Assert-CanonicalRelative $relative 'prepared-file'
            if (-not $caseFolded.Add($relative) -or $records.ContainsKey($relative)) {
                throw "SERVER_VERSION_MATRIX_PREPARED_DUPLICATE|$relative"
            }
            $records.Add($relative, [pscustomobject]@{ path=$full; size=[long]$item.Length })
        }
    }
    if ($records.Count -eq 0) { throw 'SERVER_VERSION_MATRIX_PREPARED_EMPTY' }

    $treeDigest = [Security.Cryptography.SHA256]::Create()
    $domain = [Text.Encoding]::ASCII.GetBytes($preparedTreeDomain)
    Add-DigestBytes $treeDigest $domain
    $files = [Collections.Generic.List[object]]::new()
    $totalSize = 0L
    try {
        foreach ($pair in $records.GetEnumerator()) {
            $relativeBytes = [Text.UTF8Encoding]::new($false).GetBytes($pair.Key)
            Add-DigestBytes $treeDigest (Get-Int32BigEndianBytes $relativeBytes.Length)
            Add-DigestBytes $treeDigest $relativeBytes
            Add-DigestBytes $treeDigest (Get-Int64BigEndianBytes ([long]$pair.Value.size))

            $fileDigest = [Security.Cryptography.SHA256]::Create()
            try {
                $stream = [IO.File]::Open($pair.Value.path, [IO.FileMode]::Open,
                    [IO.FileAccess]::Read, [IO.FileShare]::Read)
                try {
                    $buffer = [byte[]]::new(65536)
                    while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        [void]$treeDigest.TransformBlock($buffer, 0, $read, $buffer, 0)
                        [void]$fileDigest.TransformBlock($buffer, 0, $read, $buffer, 0)
                    }
                    [void]$fileDigest.TransformFinalBlock([byte[]]::new(0), 0, 0)
                } finally {
                    $stream.Dispose()
                }
                $after = Get-Item -LiteralPath $pair.Value.path -Force
                if ([long]$after.Length -ne [long]$pair.Value.size) {
                    throw "SERVER_VERSION_MATRIX_PREPARED_CHANGED_DURING_HASH|$($pair.Key)"
                }
                $totalSize += [long]$pair.Value.size
                [void]$files.Add([pscustomobject][ordered]@{
                    relative = $pair.Key
                    size = [long]$pair.Value.size
                    sha256 = ConvertTo-LowerHex $fileDigest.Hash
                })
            } finally { $fileDigest.Dispose() }
        }
        [void]$treeDigest.TransformFinalBlock([byte[]]::new(0), 0, 0)
        $treeSha256 = ConvertTo-LowerHex $treeDigest.Hash
    } finally {
        $treeDigest.Dispose()
    }
    return [pscustomobject]@{
        root = $root
        tree_sha256 = $treeSha256
        file_count = $files.Count
        total_size = $totalSize
        files = @($files)
    }
}

function Get-ExpectedAsset([string]$Project, [string]$Version) {
    $matches = @($expectedAssets | Where-Object {
        $_.project -ceq $Project -and $_.version -ceq $Version
    })
    if ($matches.Count -ne 1) {
        throw "SERVER_VERSION_MATRIX_EXPECTED_ASSET_MISSING|$Project|$Version"
    }
    return $matches[0]
}

function Get-AssetIdentity([object]$Asset) {
    return "$($Asset.project):$($Asset.version):$($Asset.build)"
}

function Assert-AssetManifest {
    $evidence = Read-StableJson $assetManifestPath
    $manifest = $evidence.value
    if (-not (Test-ExactProperties $manifest @(
                'schema','generated_at','prepared_tree_status','assets')) -or
            $manifest.schema -cne 'MCACE_SERVER_VERSION_MATRIX_ASSETS_V1' -or
            [string]$manifest.prepared_tree_status -cne 'DEFERRED' -or
            @($manifest.assets).Count -ne 8) {
        throw 'SERVER_VERSION_MATRIX_ASSET_MANIFEST_SCHEMA_INVALID'
    }
    try {
        # PowerShell's JSON parser materializes ISO timestamps as DateTime using
        # the host's local culture/time zone.  Do not stringify that object and
        # feed the localized value back through DateTimeOffset.Parse: zh-SG
        # renders `08/23/2026 09:44:35`, which is not parseable on every worker.
        if ($manifest.generated_at -is [DateTimeOffset]) {
            $null = [DateTimeOffset]$manifest.generated_at
        } elseif ($manifest.generated_at -is [DateTime]) {
            $null = [DateTimeOffset]$manifest.generated_at
        } else {
            $null = [DateTimeOffset]::Parse(
                [string]$manifest.generated_at,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind)
        }
    }
    catch { throw 'SERVER_VERSION_MATRIX_ASSET_MANIFEST_TIME_INVALID' }

    $expectedKeys = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($expected in $expectedAssets) {
        if (-not $expectedKeys.Add((Get-AssetIdentity $expected))) {
            throw 'SERVER_VERSION_MATRIX_EXPECTED_ASSET_DUPLICATE'
        }
    }
    $actual = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($asset in @($manifest.assets)) {
        $isProxy = $asset.project -in @('velocity','bungeecord')
        $names = @('project','version','build','url','sha256','size','channel','java_major')
        if ($isProxy) { $names += 'target_versions' }
        if (-not (Test-ExactProperties $asset $names)) {
            throw 'SERVER_VERSION_MATRIX_ASSET_ENTRY_SCHEMA_INVALID'
        }
        $key = Get-AssetIdentity $asset
        if ($actual.ContainsKey($key) -or -not $expectedKeys.Contains($key)) {
            throw "SERVER_VERSION_MATRIX_ASSET_SET_INVALID|$key"
        }
        $actual.Add($key, $asset)
        $expected = Get-ExpectedAsset ([string]$asset.project) ([string]$asset.version)
        $size = -1L
        $javaMajor = -1
        try {
            $size = [Convert]::ToInt64($asset.size)
            $javaMajor = [Convert]::ToInt32($asset.java_major)
        } catch { }
        if ([string]$asset.build -cne [string]$expected.build -or
                [string]$asset.sha256 -cne [string]$expected.sha256 -or
                $size -ne [long]$expected.size -or
                [string]$asset.channel -cne [string]$expected.channel -or
                $javaMajor -ne [int]$expected.java_major -or
                [string]$asset.url -cne [string]$expected.url) {
            throw "SERVER_VERSION_MATRIX_ASSET_IDENTITY_MISMATCH|$key"
        }
        if ($isProxy) {
            $versions = [string[]]@($asset.target_versions)
            if (($versions -join ',') -cne ($targetVersions -join ',')) {
                throw "SERVER_VERSION_MATRIX_PROXY_TARGET_SET_INVALID|$key"
            }
        }
    }
    if ($actual.Count -ne $expectedKeys.Count) {
        throw 'SERVER_VERSION_MATRIX_ASSET_SET_INCOMPLETE'
    }

    $public = [Collections.Generic.List[object]]::new()
    $internal = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($expected in $expectedAssets) {
        $key = Get-AssetIdentity $expected
        $asset = $actual[$key]
        $isProxy = $asset.project -in @('velocity','bungeecord')
        $path = if ($isProxy) {
            Join-Path $assetRoot (Join-Path ([string]$asset.project) `
                (Join-Path ([string]$asset.version) 'server.jar'))
        } else {
            Join-Path $assetRoot (Join-Path ([string]$asset.project) `
                (Join-Path ([string]$asset.version) (Join-Path ([string]$asset.build) 'server.jar')))
        }
        $digest = Get-StableFileDigest $path
        if ($digest.sha256 -cne [string]$asset.sha256 -or
                $digest.size -ne [long]$expected.size) {
            throw "SERVER_VERSION_MATRIX_ASSET_BYTES_MISMATCH|$key"
        }
        $entry = [pscustomobject][ordered]@{
            project = [string]$asset.project
            version = [string]$asset.version
            build = [string]$asset.build
            sha256 = [string]$asset.sha256
            size = [long]$expected.size
            channel = [string]$asset.channel
            java_major = [int]$expected.java_major
        }
        [void]$public.Add($entry)
        $internal.Add($key, [pscustomobject]@{ metadata=$entry; path=$digest.path })
    }
    return [pscustomobject]@{
        manifest_sha256 = $evidence.digest.sha256
        assets = @($public)
        by_identity = $internal
    }
}

function Assert-PreparedManifest([object]$AssetState) {
    $evidence = Read-StableJson $preparedManifestPath
    $manifest = $evidence.value
    if (-not (Test-ExactProperties $manifest @('schema','generated_at','roots','trees')) -or
            $manifest.schema -cne 'MCACE_SERVER_VERSION_MATRIX_PREPARED_V1' -or
            ((@($manifest.roots) -join ',') -cne ($preparedRoots -join ',')) -or
            @($manifest.trees).Count -ne 6) {
        throw 'SERVER_VERSION_MATRIX_PREPARED_MANIFEST_SCHEMA_INVALID'
    }
    try {
        if ($manifest.generated_at -is [DateTimeOffset]) {
            $null = [DateTimeOffset]$manifest.generated_at
        } elseif ($manifest.generated_at -is [DateTime]) {
            $null = [DateTimeOffset]$manifest.generated_at
        } else {
            $null = [DateTimeOffset]::Parse(
                [string]$manifest.generated_at,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind)
        }
    }
    catch { throw 'SERVER_VERSION_MATRIX_PREPARED_MANIFEST_TIME_INVALID' }

    $trees = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($tree in @($manifest.trees)) {
        if (-not (Test-ExactProperties $tree @('project','version','build','server_sha256','files')) -or
                $tree.project -notin @('paper','folia') -or @($tree.files).Count -eq 0) {
            throw 'SERVER_VERSION_MATRIX_PREPARED_TREE_SCHEMA_INVALID'
        }
        $key = Get-AssetIdentity $tree
        if ($trees.ContainsKey($key)) {
            throw "SERVER_VERSION_MATRIX_PREPARED_TREE_DUPLICATE|$key"
        }
        $trees.Add($key, $tree)
    }

    $public = [Collections.Generic.List[object]]::new()
    $internal = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($expected in @($expectedAssets | Where-Object { $_.project -in @('paper','folia') })) {
        $key = Get-AssetIdentity $expected
        if (-not $trees.ContainsKey($key)) {
            throw "SERVER_VERSION_MATRIX_PREPARED_TREE_MISSING|$key"
        }
        $tree = $trees[$key]
        if ([string]$tree.server_sha256 -cne [string]$expected.sha256) {
            throw "SERVER_VERSION_MATRIX_PREPARED_SERVER_MISMATCH|$key"
        }
        $preparedPath = Join-Path $assetRoot (Join-Path ([string]$expected.project) `
            (Join-Path ([string]$expected.version) (Join-Path ([string]$expected.build) 'prepared')))
        $snapshot = Get-PreparedTreeSnapshot $preparedPath
        $expectedFiles = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
        $caseFolded = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($file in @($tree.files)) {
            if (-not (Test-ExactProperties $file @('relative','size','sha256'))) {
                throw "SERVER_VERSION_MATRIX_PREPARED_FILE_SCHEMA_INVALID|$key"
            }
            $relative = [string]$file.relative
            Assert-CanonicalRelative $relative 'prepared-manifest-file'
            if (-not $caseFolded.Add($relative) -or $expectedFiles.ContainsKey($relative)) {
                throw "SERVER_VERSION_MATRIX_PREPARED_FILE_DUPLICATE|$key|$relative"
            }
            $expectedFiles.Add($relative, $file)
        }
        if ($expectedFiles.Count -ne $snapshot.file_count) {
            throw "SERVER_VERSION_MATRIX_PREPARED_FILE_COUNT_MISMATCH|$key"
        }
        foreach ($actualFile in @($snapshot.files)) {
            if (-not $expectedFiles.ContainsKey([string]$actualFile.relative)) {
                throw "SERVER_VERSION_MATRIX_PREPARED_UNKNOWN_FILE|$key|$($actualFile.relative)"
            }
            $expectedFile = $expectedFiles[[string]$actualFile.relative]
            if ([Convert]::ToInt64($expectedFile.size) -ne [long]$actualFile.size -or
                    [string]$expectedFile.sha256 -cne [string]$actualFile.sha256) {
                throw "SERVER_VERSION_MATRIX_PREPARED_FILE_MISMATCH|$key|$($actualFile.relative)"
            }
        }
        $entry = [pscustomobject][ordered]@{
            project = [string]$expected.project
            version = [string]$expected.version
            build = [string]$expected.build
            server_sha256 = [string]$expected.sha256
            prepared_tree_sha256 = [string]$snapshot.tree_sha256
            file_count = [int]$snapshot.file_count
            total_size = [long]$snapshot.total_size
        }
        [void]$public.Add($entry)
        $internal.Add($key, [pscustomobject]@{ metadata=$entry; path=$snapshot.root })
    }
    if ($trees.Count -ne $internal.Count) {
        throw 'SERVER_VERSION_MATRIX_PREPARED_TREE_SET_INVALID'
    }
    return [pscustomobject]@{
        manifest_sha256 = $evidence.digest.sha256
        trees = @($public)
        by_identity = $internal
    }
}

function Resolve-CachedJdk([int]$Feature) {
    $gradleUserHome = if ([string]::IsNullOrWhiteSpace($env:GRADLE_USER_HOME)) {
        Join-Path $env:USERPROFILE '.gradle'
    } else { [IO.Path]::GetFullPath($env:GRADLE_USER_HOME) }
    $jdksRoot = Assert-DirectLocalPath (Join-Path $gradleUserHome 'jdks') -Directory
    $candidates = [Collections.Generic.List[object]]::new()
    foreach ($directory in @(Get-ChildItem -LiteralPath $jdksRoot -Directory -Force -ErrorAction Stop)) {
        if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "SERVER_VERSION_MATRIX_JDK_REPARSE|$($directory.Name)"
        }
        $releasePath = Join-Path $directory.FullName 'release'
        $javaPath = Join-Path $directory.FullName 'bin\java.exe'
        if (-not (Test-Path -LiteralPath $releasePath -PathType Leaf) -or
                -not (Test-Path -LiteralPath $javaPath -PathType Leaf)) { continue }
        $releaseText = [IO.File]::ReadAllText((Assert-DirectLocalPath $releasePath), [Text.Encoding]::UTF8)
        $match = [regex]::Match($releaseText, '(?m)^JAVA_VERSION="(?<version>[^"]+)"\s*$')
        if (-not $match.Success) { continue }
        $version = $match.Groups['version'].Value
        $observedFeature = -1
        if ($version -match '^(?<feature>[0-9]+)(?:\.|$)') {
            $observedFeature = [int]$Matches['feature']
        }
        if ($observedFeature -eq $Feature) {
            [void]$candidates.Add([pscustomobject]@{
                home = Assert-DirectLocalPath $directory.FullName -Directory
                java = Assert-DirectLocalPath $javaPath
                version = $version
            })
        }
    }
    if ($candidates.Count -ne 1) {
        throw "SERVER_VERSION_MATRIX_CACHED_JDK_EXACT_ONE_REQUIRED|$Feature|$($candidates.Count)"
    }
    $candidate = $candidates[0]
    $java = Get-StableFileDigest $candidate.java
    $release = Get-StableFileDigest (Join-Path $candidate.home 'release')
    $modules = Get-StableFileDigest (Join-Path $candidate.home 'lib\modules')
    $jvm = Get-StableFileDigest (Join-Path $candidate.home 'bin\server\jvm.dll')
    return [pscustomobject]@{
        home = $candidate.home
        java = $candidate.java
        public = [pscustomobject][ordered]@{
            feature = $Feature
            version = [string]$candidate.version
            java_executable_sha256 = $java.sha256
            java_executable_size = $java.size
            release_sha256 = $release.sha256
            modules_sha256 = $modules.sha256
            modules_size = $modules.size
            jvm_sha256 = $jvm.sha256
            jvm_size = $jvm.size
        }
    }
}

function Get-DirectoryManifestDigest([string]$Root, [string]$Domain) {
    $resolvedRoot = Assert-DirectLocalPath $Root -Directory
    $prefix = $resolvedRoot.TrimEnd([char[]]@('\','/')) + [IO.Path]::DirectorySeparatorChar
    $records = [Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($item in @(Get-ChildItem -LiteralPath $resolvedRoot -Recurse -Force -ErrorAction Stop)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "SERVER_VERSION_MATRIX_DIRECTORY_REPARSE|$($item.Name)"
        }
        if ($item.PSIsContainer) { continue }
        if (-not ($item -is [IO.FileInfo])) {
            throw "SERVER_VERSION_MATRIX_DIRECTORY_ENTRY_INVALID|$($item.Name)"
        }
        $full = Assert-PathBelow $resolvedRoot $item.FullName 'directory-manifest'
        $relative = $full.Substring($prefix.Length).Replace('\','/')
        Assert-CanonicalRelative $relative 'directory-manifest'
        if ($records.ContainsKey($relative)) {
            throw "SERVER_VERSION_MATRIX_DIRECTORY_DUPLICATE|$relative"
        }
        $records.Add($relative, $full)
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    Add-DigestBytes $sha ([Text.Encoding]::ASCII.GetBytes("$Domain`0"))
    $count = 0
    $total = 0L
    try {
        foreach ($pair in $records.GetEnumerator()) {
            $digest = Get-StableFileDigest $pair.Value
            $line = "$($pair.Key)|$($digest.size)|$($digest.sha256)`n"
            Add-DigestBytes $sha ([Text.UTF8Encoding]::new($false).GetBytes($line))
            $count++
            $total += $digest.size
        }
        [void]$sha.TransformFinalBlock([byte[]]::new(0), 0, 0)
        $hash = ConvertTo-LowerHex $sha.Hash
    } finally { $sha.Dispose() }
    return [pscustomobject]@{ sha256=$hash; file_count=$count; total_size=$total }
}

function Resolve-CachedGradle961 {
    $gradleUserHome = if ([string]::IsNullOrWhiteSpace($env:GRADLE_USER_HOME)) {
        Join-Path $env:USERPROFILE '.gradle'
    } else { [IO.Path]::GetFullPath($env:GRADLE_USER_HOME) }
    $distRoot = Assert-DirectLocalPath (Join-Path $gradleUserHome 'wrapper\dists\gradle-9.6.1-bin') -Directory
    $commands = @(Get-ChildItem -LiteralPath $distRoot -Recurse -File -Filter 'gradle.bat' -Force -ErrorAction Stop |
        Where-Object { $_.FullName -match '[\\/]gradle-9\.6\.1[\\/]bin[\\/]gradle\.bat$' })
    if ($commands.Count -ne 1) {
        throw "SERVER_VERSION_MATRIX_GRADLE_9_6_1_EXACT_ONE_REQUIRED|$($commands.Count)"
    }
    $command = Assert-DirectLocalPath $commands[0].FullName
    $gradleHome = Assert-DirectLocalPath (Split-Path -Parent (Split-Path -Parent $command)) -Directory
    if ((Split-Path -Leaf $gradleHome) -cne 'gradle-9.6.1') {
        throw 'SERVER_VERSION_MATRIX_GRADLE_HOME_INVALID'
    }
    $commandDigest = Get-StableFileDigest $command
    $launcherDigest = Get-StableFileDigest (Join-Path $gradleHome 'lib\gradle-launcher-9.6.1.jar')
    $coreDigest = Get-StableFileDigest (Join-Path $gradleHome 'lib\gradle-core-9.6.1.jar')
    $manifest = Get-DirectoryManifestDigest $gradleHome 'MCACE_GRADLE_9_6_1_INSTALLATION_V1'
    return [pscustomobject]@{
        command = $command
        home = $gradleHome
        user_home = $gradleUserHome
        public = [pscustomobject][ordered]@{
            version = '9.6.1'
            command_sha256 = $commandDigest.sha256
            launcher_sha256 = $launcherDigest.sha256
            core_sha256 = $coreDigest.sha256
            installation_manifest_sha256 = $manifest.sha256
            installation_file_count = $manifest.file_count
            installation_total_size = $manifest.total_size
        }
    }
}

function Get-SourceManifest {
    $files = [Collections.Generic.SortedDictionary[string,string]]::new([StringComparer]::Ordinal)
    $repoPrefix = $repoRoot.TrimEnd([char[]]@('\','/')) + [IO.Path]::DirectorySeparatorChar
    function Add-SourceFile([string]$Candidate) {
        if (-not (Test-Path -LiteralPath $Candidate -PathType Leaf)) { return }
        $full = Assert-PathBelow $repoRoot (Assert-DirectLocalPath $Candidate) 'source-file'
        $relative = $full.Substring($repoPrefix.Length).Replace('\','/')
        Assert-CanonicalRelative $relative 'source-file'
        if ($files.ContainsKey($relative)) { return }
        $files.Add($relative, $full)
    }
    foreach ($name in @('build.gradle.kts','settings.gradle.kts','gradle.properties','gradlew','gradlew.bat')) {
        Add-SourceFile (Join-Path $repoRoot $name)
    }
    foreach ($rootName in @('gradle','fabric-modern')) {
        $rootPath = Join-Path $repoRoot $rootName
        if (-not (Test-Path -LiteralPath $rootPath -PathType Container)) { continue }
        foreach ($item in @(Get-ChildItem -LiteralPath $rootPath -Recurse -File -Force -ErrorAction Stop |
            Where-Object { $_.FullName -notmatch '[\\/](build|\.gradle)[\\/]' })) {
            Add-SourceFile $item.FullName
        }
    }
    foreach ($module in @(Get-ChildItem -LiteralPath $repoRoot -Directory -Force -ErrorAction Stop |
        Where-Object { $_.Name -like 'mcace-*' })) {
        foreach ($name in @('build.gradle.kts','gradle.lockfile')) {
            Add-SourceFile (Join-Path $module.FullName $name)
        }
        $src = Join-Path $module.FullName 'src'
        if (Test-Path -LiteralPath $src -PathType Container) {
            foreach ($item in @(Get-ChildItem -LiteralPath $src -Recurse -File -Force -ErrorAction Stop)) {
                Add-SourceFile $item.FullName
            }
        }
    }
    foreach ($path in @(
        $wrapperPath,
        $wrapperTestPath,
        (Join-Path $repoRoot 'scripts\prepare-server-version-matrix.ps1'),
        (Join-Path $repoRoot 'scripts\test-prepare-server-version-matrix.ps1'))) {
        Add-SourceFile $path
    }
    if ($files.Count -lt 20) { throw 'SERVER_VERSION_MATRIX_SOURCE_SET_TOO_SMALL' }
    $sha = [Security.Cryptography.SHA256]::Create()
    Add-DigestBytes $sha ([Text.Encoding]::ASCII.GetBytes("MCACE_SERVER_VERSION_MATRIX_SOURCE_V1`0"))
    try {
        foreach ($pair in $files.GetEnumerator()) {
            $digest = Get-StableFileDigest $pair.Value
            Add-DigestBytes $sha ([Text.UTF8Encoding]::new($false).GetBytes(
                "$($pair.Key)|$($digest.size)|$($digest.sha256)`n"))
        }
        [void]$sha.TransformFinalBlock([byte[]]::new(0),0,0)
        $hash = ConvertTo-LowerHex $sha.Hash
    } finally { $sha.Dispose() }
    return [pscustomobject]@{ sha256=$hash; file_count=$files.Count }
}

function Get-ProductJars {
    $public = [ordered]@{}
    $internal = [ordered]@{}
    foreach ($pair in $productJarRelatives.GetEnumerator()) {
        $path = Join-Path $repoRoot ($pair.Value.Replace('/','\'))
        $digest = Get-StableFileDigest $path
        $public[$pair.Key] = [pscustomobject][ordered]@{
            relative = [string]$pair.Value
            sha256 = $digest.sha256
            size = $digest.size
        }
        $internal[$pair.Key] = $digest.path
    }
    return [pscustomobject]@{ public=[pscustomobject]$public; paths=$internal }
}

function Get-MatrixDefinitions([object]$AssetState, [object]$PreparedState) {
    $protocolByVersion = [ordered]@{ '1.21.11'=774; '26.1.2'=775; '26.2'=776 }
    $javaByVersion = [ordered]@{ '1.21.11'=21; '26.1.2'=25; '26.2'=25 }
    $playLoginByVersion = [ordered]@{ '1.21.11'='0x30'; '26.1.2'='0x31'; '26.2'='0x31' }
    $definitions = [Collections.Generic.List[object]]::new()
    foreach ($version in $targetVersions) {
        foreach ($backend in @('paper','folia')) {
            $serverExpected = Get-ExpectedAsset $backend $version
            $serverKey = Get-AssetIdentity $serverExpected
            if (-not $AssetState.by_identity.ContainsKey($serverKey) -or
                    -not $PreparedState.by_identity.ContainsKey($serverKey)) {
                throw "SERVER_VERSION_MATRIX_DEFINITION_SERVER_MISSING|$serverKey"
            }
            foreach ($proxy in @('velocity','bungee')) {
                $proxyProject = if ($proxy -ceq 'velocity') { 'velocity' } else { 'bungeecord' }
                $proxyExpected = @($expectedAssets | Where-Object { $_.project -ceq $proxyProject })[0]
                $proxyKey = Get-AssetIdentity $proxyExpected
                $isFolia = $backend -ceq 'folia'
                $selector = if ($isFolia) {
                    if ($proxy -ceq 'velocity') {
                        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realVelocityModernForwardingToFoliaReturnsShadowContext'
                    } else {
                        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realBungeeIpForwardingToFoliaReturnsShadowContext'
                    }
                } else {
                    if ($proxy -ceq 'velocity') {
                        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realVelocityModernForwardingOfflinePlayerProbeReachesMCAceChannel'
                    } else {
                        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realBungeeIpForwardingOfflinePlayerProbeReachesMCAceChannel'
                    }
                }
                $lane = if ($backend -ceq 'folia' -and $version -ceq '26.2') { 'BETA' } else { 'STABLE' }
                [void]$definitions.Add([pscustomobject][ordered]@{
                    case_id = "$version-$backend-$proxy"
                    minecraft_version = $version
                    minecraft_protocol = [int]$protocolByVersion[$version]
                    server_java_feature = [int]$javaByVersion[$version]
                    backend = $backend.ToUpperInvariant()
                    proxy = $proxy.ToUpperInvariant()
                    lane = $lane
                    selector = $selector
                    enable_property = if ($isFolia) {
                        'mcace.runtime.folia-context.enabled'
                    } else { 'mcace.runtime.player-probe.enabled' }
                    raw_prefix = if ($isFolia) { "$proxy-folia-" } else { "$proxy-" }
                    expected_play_login = [string]$playLoginByVersion[$version]
                    server_key = $serverKey
                    proxy_key = $proxyKey
                    server_asset = $AssetState.by_identity[$serverKey]
                    prepared_asset = $PreparedState.by_identity[$serverKey]
                    proxy_asset = $AssetState.by_identity[$proxyKey]
                })
            }
        }
    }
    if ($definitions.Count -ne 12 -or
            @($definitions | Where-Object { $_.lane -ceq 'BETA' }).Count -ne 2) {
        throw 'SERVER_VERSION_MATRIX_DEFINITION_SET_INVALID'
    }
    return @($definitions)
}

function Get-CurrentBinding {
    $repo = Assert-DirectLocalPath $repoRoot -Directory
    $null = Assert-DirectLocalPath $wrapperPath
    $null = Assert-DirectLocalPath $wrapperTestPath
    $assetState = Assert-AssetManifest
    $preparedState = Assert-PreparedManifest $assetState
    $jdk21 = Resolve-CachedJdk 21
    $jdk25 = Resolve-CachedJdk 25
    $gradle = Resolve-CachedGradle961
    $source = Get-SourceManifest
    $products = Get-ProductJars
    $definitions = Get-MatrixDefinitions $assetState $preparedState
    $wrapper = Get-StableFileDigest $wrapperPath
    $wrapperTest = Get-StableFileDigest $wrapperTestPath

    $publicDefinitions = @($definitions | ForEach-Object {
        [pscustomobject][ordered]@{
            case_id = $_.case_id
            minecraft_version = $_.minecraft_version
            minecraft_protocol = $_.minecraft_protocol
            server_java_feature = $_.server_java_feature
            backend = $_.backend
            proxy = $_.proxy
            lane = $_.lane
            selector = $_.selector
            server_asset_identity = $_.server_key
            server_asset_sha256 = $_.server_asset.metadata.sha256
            prepared_tree_sha256 = $_.prepared_asset.metadata.prepared_tree_sha256
            proxy_asset_identity = $_.proxy_key
            proxy_asset_sha256 = $_.proxy_asset.metadata.sha256
        }
    })
    $public = [pscustomobject][ordered]@{
        target_versions = @($targetVersions)
        case_count = 12
        source_manifest_sha256 = $source.sha256
        source_file_count = $source.file_count
        wrapper_sha256 = $wrapper.sha256
        wrapper_test_sha256 = $wrapperTest.sha256
        runtime_assets_manifest_sha256 = $assetState.manifest_sha256
        prepared_manifest_sha256 = $preparedState.manifest_sha256
        assets = @($assetState.assets)
        prepared_trees = @($preparedState.trees)
        root_jdk = $jdk21.public
        server_jdks = @($jdk21.public, $jdk25.public)
        gradle = $gradle.public
        product_jars = $products.public
        definitions = $publicDefinitions
    }
    return [pscustomobject]@{
        public = $public
        repository = $repo
        asset_state = $assetState
        prepared_state = $preparedState
        jdk21 = $jdk21
        jdk25 = $jdk25
        gradle = $gradle
        products = $products
        definitions = $definitions
    }
}

function ConvertTo-CompactJsonBytes([object]$Value, [int]$Depth = 30) {
    $json = ($Value | ConvertTo-Json -Depth $Depth -Compress) + "`n"
    return [Text.UTF8Encoding]::new($false).GetBytes($json)
}

function Assert-SanitizedEvidenceBytes([byte[]]$Bytes, [string]$Label) {
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
    foreach ($secret in @($repoRoot, $env:USERPROFILE)) {
        if (-not [string]::IsNullOrWhiteSpace($secret) -and
                $text.IndexOf($secret, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "SERVER_VERSION_MATRIX_EVIDENCE_PATH_DISCLOSURE|$Label"
        }
    }
    if ($text -match '(?i)server-private-key|forwarding\.secret|private[-_ ]?key.{0,8}(base64|pk8)') {
        throw "SERVER_VERSION_MATRIX_EVIDENCE_SECRET_DISCLOSURE|$Label"
    }
}

function Compare-PublicBinding([object]$Expected, [object]$Actual) {
    $expectedBytes = ConvertTo-CompactJsonBytes $Expected
    $actualBytes = ConvertTo-CompactJsonBytes $Actual
    if ((Get-BytesSha256 $expectedBytes) -cne (Get-BytesSha256 $actualBytes)) {
        throw 'SERVER_VERSION_MATRIX_CURRENT_BINDING_MISMATCH'
    }
}

function Get-StrictGradleFlags {
    return @(
        '--rerun-tasks', '--offline', '--dependency-verification=strict',
        '--no-build-cache', '--no-configuration-cache',
        '--no-daemon', '--no-parallel', '--max-workers=1', '--console=plain'
    )
}

function Invoke-StrictGradle {
    param(
        [Parameter(Mandatory)][object]$Current,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$LogName
    )
    if (-not (Test-Path -LiteralPath $invocationRoot -PathType Container)) {
        $null = Assert-ExistingOrParentDirect $invocationRoot
        [void][IO.Directory]::CreateDirectory($invocationRoot)
    }
    $null = Assert-DirectLocalPath $invocationRoot -Directory
    $safeName = $LogName -replace '[^A-Za-z0-9._-]', '_'
    $logPath = Join-Path $invocationRoot ($safeName + '.log')
    if (Test-Path -LiteralPath $logPath) { [IO.File]::Delete((Assert-DirectLocalPath $logPath)) }
    $oldJavaHome = $env:JAVA_HOME
    $oldPath = $env:PATH
    $oldErrorActionPreference = $ErrorActionPreference
    $exitCode = $null
    try {
        $env:JAVA_HOME = $Current.jdk21.home
        $env:PATH = (Join-Path $Current.jdk21.home 'bin') + [IO.Path]::PathSeparator + $oldPath
        # Windows PowerShell 5 surfaces redirected native stderr as nonterminating ErrorRecords.
        # Keep those lines visible/logged; the native exit code remains the authoritative gate.
        $ErrorActionPreference = 'Continue'
        $allArguments = @($Arguments) + @(Get-StrictGradleFlags) + @(
            '--gradle-user-home', $Current.gradle.user_home,
            '--project-dir', $repoRoot)
        & $Current.gradle.command @allArguments 2>&1 |
            ForEach-Object { $_.ToString() } |
            Tee-Object -FilePath $logPath -ErrorAction Stop |
            Out-Host
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldErrorActionPreference
        $env:JAVA_HOME = $oldJavaHome
        $env:PATH = $oldPath
    }
    if ($null -eq $exitCode -or $exitCode -ne 0) {
        throw "SERVER_VERSION_MATRIX_GRADLE_FAILED|$LogName|$exitCode"
    }
    return (Get-StableFileDigest $logPath)
}

function Invoke-ProductBuild([object]$Tooling) {
    $arguments = @(
        ':mcace-server-velocity:shadowJar',
        ':mcace-server-bungeecord:shadowJar',
        ':mcace-server-paper:shadowJar',
        ':mcace-runtime-integration:testClasses'
    )
    $null = Invoke-StrictGradle $Tooling $arguments '00-product-build'
}

function Test-JsonBoolean([object]$Value) { return $Value -is [bool] }
function Test-JsonInteger([object]$Value) {
    return $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or
        $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64]
}

function ConvertTo-ExactDateTimeOffset([object]$Value, [string]$Label) {
    $text = if ($Value -is [DateTimeOffset]) {
        ([DateTimeOffset]$Value).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    } elseif ($Value -is [DateTime]) {
        ([DateTime]$Value).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    } elseif ($Value -is [string]) {
        [string]$Value
    } else {
        throw "SERVER_VERSION_MATRIX_TIMESTAMP_INVALID|$Label"
    }
    try {
        return [DateTimeOffset]::Parse(
            $text,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    } catch {
        throw "SERVER_VERSION_MATRIX_TIMESTAMP_INVALID|$Label"
    }
}

function Test-ExactDateTimeOffsetInstant([object]$Left, [object]$Right, [string]$Label) {
    $leftInstant = ConvertTo-ExactDateTimeOffset $Left "$Label.left"
    $rightInstant = ConvertTo-ExactDateTimeOffset $Right "$Label.right"
    return $leftInstant.Ticks -eq $rightInstant.Ticks
}

function Resolve-RepositoryRelative([string]$Relative, [string]$Label) {
    Assert-CanonicalRelative $Relative $Label
    $candidate = [IO.Path]::GetFullPath((Join-Path $repoRoot ($Relative.Replace('/','\'))))
    $null = Assert-PathBelow $repoRoot $candidate $Label
    return Assert-DirectLocalPath $candidate
}

function Assert-NoSensitiveRunArtifacts([string]$RunRoot) {
    $root = Assert-DirectLocalPath $RunRoot -Directory
    foreach ($item in @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction Stop)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "SERVER_VERSION_MATRIX_RAW_REPARSE|$($item.Name)"
        }
        if ($item.PSIsContainer) { continue }
        $name = $item.Name.ToLowerInvariant()
        if ($name -eq 'forwarding.secret' -or $name -match 'private[-_]?key' -or
                $name.EndsWith('.pk8')) {
            throw "SERVER_VERSION_MATRIX_SENSITIVE_RUN_ARTIFACT_RETAINED|$name"
        }
        if ([long]$item.Length -le 1048576) {
            $bytes = [IO.File]::ReadAllBytes((Assert-DirectLocalPath $item.FullName))
            $ascii = [Text.Encoding]::ASCII.GetString($bytes)
            if ($ascii -match '-----BEGIN (?:RSA |EC )?PRIVATE KEY-----') {
                throw "SERVER_VERSION_MATRIX_PRIVATE_KEY_CONTENT_RETAINED|$name"
            }
        }
    }
}

function Get-RunProcesses([string]$RunRoot) {
    $needle = [IO.Path]::GetFullPath($RunRoot)
    $result = [Collections.Generic.List[object]]::new()
    try {
        foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$process.CommandLine) -and
                    ([string]$process.CommandLine).IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                [void]$result.Add($process)
            }
        }
    } catch {
        throw 'SERVER_VERSION_MATRIX_PROCESS_ENUMERATION_FAILED'
    }
    return @($result)
}

function Assert-RunRootBytes {
    param(
        [Parameter(Mandatory)][object]$Definition,
        [Parameter(Mandatory)][object]$Current,
        [Parameter(Mandatory)][string]$RunRoot
    )
    $root = Assert-DirectLocalPath $RunRoot -Directory
    $proxyJarName = if ($Definition.proxy -ceq 'VELOCITY') { 'velocity.jar' } else { 'BungeeCord.jar' }
    $backendJarName = if ($Definition.backend -ceq 'FOLIA') { 'folia.jar' } else { 'paper.jar' }
    $proxyJar = Get-StableFileDigest (Join-Path $root (Join-Path 'proxy' $proxyJarName))
    $backendJar = Get-StableFileDigest (Join-Path $root (Join-Path 'paper' $backendJarName))
    $proxyPlugin = Get-StableFileDigest (Join-Path $root 'proxy\plugins\mcace.jar')
    $backendPlugin = Get-StableFileDigest (Join-Path $root 'paper\plugins\mcace.jar')
    # The live Folia/Paper work tree is mutable: newer Folia bootstrap versions can rewrite
    # versions/<minecraft>/<server>.jar during startup. Verify the immutable pre-launch snapshot
    # retained by the harness instead of mistaking that legitimate bootstrap rewrite for asset
    # drift. The backend/proxy/plugin bytes below remain checked from the live run tree.
    $preparedSnapshotRoot = Join-Path $root 'prepared-snapshot'
    $preparedCopy = Get-PreparedTreeSnapshot $preparedSnapshotRoot
    $expectedProxyProduct = if ($Definition.proxy -ceq 'VELOCITY') {
        $Current.public.product_jars.velocity
    } else { $Current.public.product_jars.bungee }
    if ($proxyJar.sha256 -cne $Definition.proxy_asset.metadata.sha256 -or
            $proxyJar.size -ne $Definition.proxy_asset.metadata.size -or
            $backendJar.sha256 -cne $Definition.server_asset.metadata.sha256 -or
            $backendJar.size -ne $Definition.server_asset.metadata.size -or
            $proxyPlugin.sha256 -cne $expectedProxyProduct.sha256 -or
            $proxyPlugin.size -ne $expectedProxyProduct.size -or
            $backendPlugin.sha256 -cne $Current.public.product_jars.paper.sha256 -or
            $backendPlugin.size -ne $Current.public.product_jars.paper.size -or
            $preparedCopy.tree_sha256 -cne $Definition.prepared_asset.metadata.prepared_tree_sha256 -or
            $preparedCopy.file_count -ne $Definition.prepared_asset.metadata.file_count -or
            $preparedCopy.total_size -ne $Definition.prepared_asset.metadata.total_size) {
        throw "SERVER_VERSION_MATRIX_RUN_ROOT_BYTES_MISMATCH|$($Definition.case_id)"
    }
    return [pscustomobject][ordered]@{
        proxy_jar_sha256 = $proxyJar.sha256
        proxy_jar_size = $proxyJar.size
        backend_jar_sha256 = $backendJar.sha256
        backend_jar_size = $backendJar.size
        proxy_plugin_sha256 = $proxyPlugin.sha256
        proxy_plugin_size = $proxyPlugin.size
        backend_plugin_sha256 = $backendPlugin.sha256
        backend_plugin_size = $backendPlugin.size
        prepared_tree_sha256 = $preparedCopy.tree_sha256
        prepared_file_count = $preparedCopy.file_count
        prepared_total_size = $preparedCopy.total_size
    }
}

function Assert-RawCaseReport {
    param(
        [Parameter(Mandatory)][object]$Definition,
        [Parameter(Mandatory)][object]$Current,
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)][DateTimeOffset]$InvocationStarted,
        [Parameter(Mandatory)][DateTimeOffset]$InvocationFinished,
        [switch]$ReportOnlyValidation
    )
    $evidence = Read-StableJson $ReportPath
    $report = $evidence.value
    $names = @(
        'schema','proxy','backend_platform','backend_minecraft_version','forwarding_mode',
        'forwarding_configured','proxy_port','backend_port','tcp_connected','login_success',
        'compression_seen','configuration_finished','mcace_server_hello','mcace_auth_result',
        'mcace_auth_accepted','backend_admission','backend_context_shadow_audit','channels',
        'packet_trace','limitations','cleanup_process_ids','remaining_run_processes')
    $forwarding = if ($Definition.proxy -ceq 'VELOCITY') {
        'velocity-modern'
    } else { 'bungee-ip-forwarding' }
    if (-not (Test-ExactProperties $report $names) -or
            -not (Test-JsonInteger $report.schema) -or [int]$report.schema -ne 4 -or
            [string]$report.proxy -cne $Definition.proxy -or
            [string]$report.backend_platform -cne $Definition.backend -or
            [string]$report.backend_minecraft_version -cne $Definition.minecraft_version -or
            [string]$report.forwarding_mode -cne $forwarding) {
        throw "SERVER_VERSION_MATRIX_RAW_IDENTITY_INVALID|$($Definition.case_id)"
    }
    foreach ($name in @(
        'forwarding_configured','tcp_connected','login_success','compression_seen',
        'configuration_finished','mcace_server_hello','mcace_auth_result','mcace_auth_accepted',
        'backend_admission','backend_context_shadow_audit')) {
        if (-not (Test-JsonBoolean $report.$name) -or -not [bool]$report.$name) {
            throw "SERVER_VERSION_MATRIX_RAW_ASSERTION_FAILED|$($Definition.case_id)|$name"
        }
    }
    if (@($report.limitations).Count -ne 0 -or @($report.remaining_run_processes).Count -ne 0) {
        throw "SERVER_VERSION_MATRIX_RAW_LIMITATION_OR_RESIDUE|$($Definition.case_id)"
    }
    $cleanupIds = @($report.cleanup_process_ids)
    if ($cleanupIds.Count -lt 2 -or @($cleanupIds | Where-Object {
                -not (Test-JsonInteger $_) -or [long]$_ -le 0
            }).Count -ne 0) {
        throw "SERVER_VERSION_MATRIX_RAW_CLEANUP_IDS_INVALID|$($Definition.case_id)"
    }
    if (@($report.channels | Where-Object { [string]$_ -ceq 'mcace:handshake' }).Count -lt 1 -or
            @($report.packet_trace | Where-Object {
                [string]$_ -ceq ('PLAY:' + $Definition.expected_play_login)
            }).Count -ne 1) {
        throw "SERVER_VERSION_MATRIX_RAW_PROTOCOL_TRACE_INVALID|$($Definition.case_id)"
    }

    $writeAt = ([DateTimeOffset]$evidence.digest.last_write_utc).ToUniversalTime()
    if (-not $ReportOnlyValidation) {
        if ($writeAt -lt $InvocationStarted.ToUniversalTime().AddSeconds(-2) -or
                $writeAt -gt $InvocationFinished.ToUniversalTime().AddSeconds(2)) {
            throw "SERVER_VERSION_MATRIX_RAW_FRESHNESS_INVALID|$($Definition.case_id)"
        }
    }
    $runRoot = Split-Path -Parent $evidence.digest.path
    $runRoot = Assert-DirectLocalPath $runRoot -Directory
    $null = Assert-PathBelow $rawRunsRoot $runRoot 'raw-run-root'
    $expectedPrefix = [string]$Definition.raw_prefix
    if (-not (Split-Path -Leaf $runRoot).StartsWith($expectedPrefix, [StringComparison]::Ordinal)) {
        throw "SERVER_VERSION_MATRIX_RAW_PREFIX_INVALID|$($Definition.case_id)"
    }
    Assert-NoSensitiveRunArtifacts $runRoot
    if (@(Get-RunProcesses $runRoot).Count -ne 0) {
        throw "SERVER_VERSION_MATRIX_RUN_PROCESS_RETAINED|$($Definition.case_id)"
    }
    $runBytes = Assert-RunRootBytes $Definition $Current $runRoot
    $relative = $evidence.digest.path.Substring($repoRoot.Length + 1).Replace('\','/')
    Assert-CanonicalRelative $relative 'raw-report'
    return [pscustomobject][ordered]@{
        case_id = $Definition.case_id
        raw_schema = 4
        minecraft_version = $Definition.minecraft_version
        minecraft_protocol = $Definition.minecraft_protocol
        server_java_feature = $Definition.server_java_feature
        backend = $Definition.backend
        proxy = $Definition.proxy
        lane = $Definition.lane
        selector = $Definition.selector
        invocation_started_at = $InvocationStarted.ToUniversalTime().ToString('o')
        invocation_finished_at = $InvocationFinished.ToUniversalTime().ToString('o')
        raw_report = $relative
        raw_report_sha256 = $evidence.digest.sha256
        raw_report_size = $evidence.digest.size
        raw_report_last_write_at = $writeAt.ToString('o')
        server_asset_identity = $Definition.server_key
        proxy_asset_identity = $Definition.proxy_key
        run_root = $runBytes
        cleanup_process_count = $cleanupIds.Count
        remaining_run_process_count = 0
        sensitive_artifact_count = 0
        passed = $true
    }
}

function Get-RawRunDirectorySet {
    $comparer = if ([IO.Path]::DirectorySeparatorChar -eq '\') {
        [StringComparer]::OrdinalIgnoreCase
    } else { [StringComparer]::Ordinal }
    $set = [Collections.Generic.HashSet[string]]::new($comparer)
    if (-not (Test-Path -LiteralPath $rawRunsRoot -PathType Container)) { return ,$set }
    $null = Assert-DirectLocalPath $rawRunsRoot -Directory
    foreach ($directory in @(Get-ChildItem -LiteralPath $rawRunsRoot -Directory -Force -ErrorAction Stop)) {
        if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "SERVER_VERSION_MATRIX_RAW_RUN_REPARSE|$($directory.Name)"
        }
        [void]$set.Add([IO.Path]::GetFullPath($directory.FullName))
    }
    # PowerShell enumerates collection output; preserve the empty HashSet as a
    # single object so the first matrix case can pass it to Find-FreshRawReport.
    return ,$set
}

function Find-FreshRawReport {
    param(
        [Parameter(Mandatory)][object]$Definition,
        [Parameter(Mandatory)]$BeforeDirectories,
        [Parameter(Mandatory)][DateTimeOffset]$Started,
        [Parameter(Mandatory)][DateTimeOffset]$Finished
    )
    if (-not (Test-Path -LiteralPath $rawRunsRoot -PathType Container)) {
        throw "SERVER_VERSION_MATRIX_RAW_RUNS_MISSING|$($Definition.case_id)"
    }
    $candidates = [Collections.Generic.List[object]]::new()
    foreach ($directory in @(Get-ChildItem -LiteralPath $rawRunsRoot -Directory -Force -ErrorAction Stop)) {
        $full = [IO.Path]::GetFullPath($directory.FullName)
        if ($BeforeDirectories.Contains($full) -or
                -not $directory.Name.StartsWith([string]$Definition.raw_prefix,
                    [StringComparison]::Ordinal)) { continue }
        $path = Join-Path $full 'report.json'
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $digest = Get-StableFileDigest $path
        $write = ([DateTimeOffset]$digest.last_write_utc).ToUniversalTime()
        if ($write -ge $Started.ToUniversalTime().AddSeconds(-2) -and
                $write -le $Finished.ToUniversalTime().AddSeconds(2)) {
            [void]$candidates.Add($digest)
        }
    }
    if ($candidates.Count -ne 1) {
        throw "SERVER_VERSION_MATRIX_FRESH_RAW_EXACT_ONE_REQUIRED|$($Definition.case_id)|$($candidates.Count)"
    }
    return $candidates[0].path
}

function Invoke-MatrixCase([object]$Definition, [object]$Current, [int]$Ordinal) {
    $before = Get-RawRunDirectorySet
    $serverJdk = if ($Definition.server_java_feature -eq 21) {
        $Current.jdk21
    } else { $Current.jdk25 }
    $properties = @(
        "-D$($Definition.enable_property)=true",
        "-Dmcace.runtime.backend-kind=$($Definition.backend)",
        "-Dmcace.runtime.minecraft-version=$($Definition.minecraft_version)",
        "-Dmcace.runtime.minecraft-protocol=$($Definition.minecraft_protocol)",
        "-Dmcace.runtime.server-java-feature=$($Definition.server_java_feature)",
        "-Dmcace.runtime.backend.jar=$($Definition.server_asset.path)",
        "-Dmcace.runtime.backend.jar.sha256=$($Definition.server_asset.metadata.sha256)",
        "-Dmcace.runtime.backend.prepared-root=$($Definition.prepared_asset.path)",
        "-Dmcace.runtime.backend.prepared-root.sha256=$($Definition.prepared_asset.metadata.prepared_tree_sha256)",
        "-Dmcace.runtime.server-java=$($serverJdk.java)",
        "-Dmcace.runtime.server-java.sha256=$($serverJdk.public.java_executable_sha256)"
    )
    if ($Definition.proxy -ceq 'VELOCITY') {
        $properties += "-Dmcace.runtime.velocity.jar=$($Definition.proxy_asset.path)"
        $properties += "-Dmcace.runtime.velocity.jar.sha256=$($Definition.proxy_asset.metadata.sha256)"
    } else {
        $properties += "-Dmcace.runtime.bungee.jar=$($Definition.proxy_asset.path)"
        $properties += "-Dmcace.runtime.bungee.jar.sha256=$($Definition.proxy_asset.metadata.sha256)"
    }
    $arguments = @($properties) + @(
        ':mcace-runtime-integration:test', '--tests', [string]$Definition.selector)
    $started = [DateTimeOffset]::UtcNow
    $log = Invoke-StrictGradle $Current $arguments ('{0:d2}-{1}' -f $Ordinal,$Definition.case_id)
    $finished = [DateTimeOffset]::UtcNow
    $reportPath = Find-FreshRawReport $Definition $before $started $finished
    $result = Assert-RawCaseReport $Definition $Current $reportPath $started $finished
    return [pscustomobject]@{ case=$result; invocation_log_sha256=$log.sha256 }
}

function Assert-CaseBinding {
    param(
        [Parameter(Mandatory)][object]$Case,
        [Parameter(Mandatory)][object]$Definition,
        [Parameter(Mandatory)][object]$Current
    )
    $names = @(
        'case_id','raw_schema','minecraft_version','minecraft_protocol','server_java_feature','backend','proxy',
        'lane','selector','invocation_started_at','invocation_finished_at','raw_report',
        'raw_report_sha256','raw_report_size','raw_report_last_write_at','server_asset_identity',
        'proxy_asset_identity','run_root','cleanup_process_count','remaining_run_process_count',
        'sensitive_artifact_count','passed')
    if (-not (Test-ExactProperties $Case $names) -or
            [string]$Case.case_id -cne $Definition.case_id -or
            [int]$Case.raw_schema -ne 4 -or
            [string]$Case.minecraft_version -cne $Definition.minecraft_version -or
            [int]$Case.minecraft_protocol -ne $Definition.minecraft_protocol -or
            [int]$Case.server_java_feature -ne $Definition.server_java_feature -or
            [string]$Case.backend -cne $Definition.backend -or
            [string]$Case.proxy -cne $Definition.proxy -or
            [string]$Case.lane -cne $Definition.lane -or
            [string]$Case.selector -cne $Definition.selector -or
            [string]$Case.server_asset_identity -cne $Definition.server_key -or
            [string]$Case.proxy_asset_identity -cne $Definition.proxy_key -or
            -not (Test-JsonBoolean $Case.passed) -or -not $Case.passed -or
            [int]$Case.cleanup_process_count -lt 2 -or
            [int]$Case.remaining_run_process_count -ne 0 -or
            [int]$Case.sensitive_artifact_count -ne 0) {
        throw "SERVER_VERSION_MATRIX_CASE_BINDING_INVALID|$($Definition.case_id)"
    }
    $started = ConvertTo-ExactDateTimeOffset $Case.invocation_started_at 'invocation_started_at'
    $finished = ConvertTo-ExactDateTimeOffset $Case.invocation_finished_at 'invocation_finished_at'
    $writeAt = ConvertTo-ExactDateTimeOffset $Case.raw_report_last_write_at `
        'raw_report_last_write_at'
    if ($finished -lt $started -or $writeAt -lt $started.AddSeconds(-2) -or
            $writeAt -gt $finished.AddSeconds(2)) {
        throw "SERVER_VERSION_MATRIX_CASE_TIME_INVALID|$($Definition.case_id)"
    }
    $rawPath = Resolve-RepositoryRelative ([string]$Case.raw_report) 'raw-report-binding'
    $null = Assert-PathBelow $rawRunsRoot $rawPath 'raw-report-binding'
    $actual = Assert-RawCaseReport $Definition $Current $rawPath $started $finished -ReportOnlyValidation
    $actualWriteAt = ConvertTo-ExactDateTimeOffset $actual.raw_report_last_write_at `
        'actual_raw_report_last_write_at'
    if ([string]$actual.raw_report_sha256 -cne [string]$Case.raw_report_sha256 -or
            [long]$actual.raw_report_size -ne [long]$Case.raw_report_size -or
            -not (Test-ExactDateTimeOffsetInstant $actualWriteAt $writeAt `
                'raw_report_last_write_at') -or
            (Get-BytesSha256 (ConvertTo-CompactJsonBytes $actual.run_root)) -cne
                (Get-BytesSha256 (ConvertTo-CompactJsonBytes $Case.run_root))) {
        throw "SERVER_VERSION_MATRIX_RAW_CURRENT_MISMATCH|$($Definition.case_id)"
    }
}

function Assert-Report {
    param(
        [Parameter(Mandatory)][object]$Report,
        [Parameter(Mandatory)][object]$Current
    )
    $names = @(
        'schema','generated_at','source_mode','target_versions','expected_case_count',
        'observed_case_count','stable_case_count','beta_case_count','all_cases_passed',
        'cleanup_all_zero','cases')
    if (-not (Test-ExactProperties $Report $names) -or
            [string]$Report.schema -cne $reportSchema -or
            [string]$Report.source_mode -cne 'EXECUTED' -or
            ((@($Report.target_versions) -join ',') -cne ($targetVersions -join ',')) -or
            [int]$Report.expected_case_count -ne 12 -or [int]$Report.observed_case_count -ne 12 -or
            [int]$Report.stable_case_count -ne 10 -or [int]$Report.beta_case_count -ne 2 -or
            -not (Test-JsonBoolean $Report.all_cases_passed) -or -not $Report.all_cases_passed -or
            -not (Test-JsonBoolean $Report.cleanup_all_zero) -or -not $Report.cleanup_all_zero -or
            @($Report.cases).Count -ne 12) {
        throw 'SERVER_VERSION_MATRIX_REPORT_INVALID'
    }
    try {
        # ConvertFrom-Json materializes ISO timestamps as DateTime on Windows.  Feeding
        # its localized string form back to DateTimeOffset.Parse breaks on zh-SG workers
        # (for example, `08/24/2026 19:25:47`).  Normalize the object itself and use the
        # invariant helper for string values.
        $generated = ConvertTo-ExactDateTimeOffset $Report.generated_at 'report.generated_at'
    } catch { throw 'SERVER_VERSION_MATRIX_REPORT_TIME_INVALID' }
    $age = [DateTimeOffset]::UtcNow - $generated.ToUniversalTime()
    if ($age.TotalMinutes -lt 0 -or $age.TotalMinutes -gt $MaximumReportAgeMinutes) {
        throw 'SERVER_VERSION_MATRIX_REPORT_STALE'
    }

    for ($index = 0; $index -lt $Current.definitions.Count; $index++) {
        $definition = $Current.definitions[$index]
        $case = @($Report.cases)[$index]
        Assert-CaseBinding $case $definition $Current
        $finished = ConvertTo-ExactDateTimeOffset $case.invocation_finished_at `
            "case[$index].invocation_finished_at"
        if ($finished.ToUniversalTime() -gt $generated.ToUniversalTime()) {
            throw "SERVER_VERSION_MATRIX_CASE_AFTER_REPORT|$($definition.case_id)"
        }
    }
}

function Assert-Binding {
    param(
        [Parameter(Mandatory)][object]$Binding,
        [Parameter(Mandatory)][string]$ReportSha256,
        [Parameter(Mandatory)][object]$Report,
        [Parameter(Mandatory)][object]$Current
    )
    $names = @(
        'schema','generated_at','report_schema','report_generated_at','report_sha256',
        'source_mode','current_sha256','current','passed')
    $expectedCurrentBytes = ConvertTo-CompactJsonBytes $Current.public
    $expectedCurrentSha256 = Get-BytesSha256 $expectedCurrentBytes
    if (-not (Test-ExactProperties $Binding $names) -or
            [string]$Binding.schema -cne $bindingSchema -or
            [string]$Binding.generated_at -cne [string]$Report.generated_at -or
            [string]$Binding.report_schema -cne $reportSchema -or
            [string]$Binding.report_generated_at -cne [string]$Report.generated_at -or
            [string]$Binding.report_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Binding.report_sha256 -cne $ReportSha256 -or
            [string]$Binding.source_mode -cne 'EXECUTED' -or
            [string]$Binding.current_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Binding.current_sha256 -cne $expectedCurrentSha256 -or
            -not (Test-JsonBoolean $Binding.passed) -or -not $Binding.passed) {
        throw 'SERVER_VERSION_MATRIX_BINDING_INVALID'
    }
    Compare-PublicBinding $Current.public $Binding.current
}

function Assert-Commit {
    param(
        [Parameter(Mandatory)][object]$Commit,
        [Parameter(Mandatory)][string]$ReportSha256,
        [Parameter(Mandatory)][string]$BindingSha256,
        [Parameter(Mandatory)][object]$Report
    )
    $names = @(
        'schema','generated_at','report_schema','binding_schema','report_sha256',
        'binding_sha256','committed')
    if (-not (Test-ExactProperties $Commit $names) -or
            [string]$Commit.schema -cne $commitSchema -or
            [string]$Commit.generated_at -cne [string]$Report.generated_at -or
            [string]$Commit.report_schema -cne $reportSchema -or
            [string]$Commit.binding_schema -cne $bindingSchema -or
            [string]$Commit.report_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Commit.report_sha256 -cne $ReportSha256 -or
            [string]$Commit.binding_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Commit.binding_sha256 -cne $BindingSha256 -or
            -not (Test-JsonBoolean $Commit.committed) -or -not $Commit.committed) {
        throw 'SERVER_VERSION_MATRIX_COMMIT_INVALID'
    }
}

function Assert-ExactEvidenceDirectory([string]$Directory, [switch]$AllowStaging) {
    $root = Assert-DirectLocalPath $Directory -Directory
    $name = Split-Path -Leaf $root
    if ($AllowStaging) {
        if (-not $name.StartsWith('.staging-', [StringComparison]::Ordinal)) {
            throw 'SERVER_VERSION_MATRIX_STAGING_NAME_INVALID'
        }
    } elseif ($name -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{7}Z$') {
        throw 'SERVER_VERSION_MATRIX_EVIDENCE_RUN_NAME_INVALID'
    }
    $entries = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
    if ($entries.Count -ne 3) { throw 'SERVER_VERSION_MATRIX_EVIDENCE_TRIPLET_REQUIRED' }
    $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entryName in @('report.json','binding.json','commit.json')) {
        [void]$expected.Add($entryName)
    }
    foreach ($entry in $entries) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                $entry.PSIsContainer -or -not $expected.Remove([string]$entry.Name)) {
            throw "SERVER_VERSION_MATRIX_EVIDENCE_ENTRY_INVALID|$($entry.Name)"
        }
    }
    if ($expected.Count -ne 0) { throw 'SERVER_VERSION_MATRIX_EVIDENCE_TRIPLET_INCOMPLETE' }
    return $root
}

function Assert-EvidenceTriplet {
    param(
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)][object]$Current,
        [switch]$AllowStaging
    )
    $resolvedReport = Assert-DirectLocalPath $ReportPath
    $directory = Assert-ExactEvidenceDirectory (Split-Path -Parent $resolvedReport) `
        -AllowStaging:$AllowStaging
    $bindingPath = Join-Path $directory 'binding.json'
    $commitPath = Join-Path $directory 'commit.json'
    $reportEvidence = Read-StableJson $resolvedReport
    $bindingEvidence = Read-StableJson $bindingPath
    $commitEvidence = Read-StableJson $commitPath
    Assert-SanitizedEvidenceBytes $reportEvidence.bytes 'report'
    Assert-SanitizedEvidenceBytes $bindingEvidence.bytes 'binding'
    Assert-SanitizedEvidenceBytes $commitEvidence.bytes 'commit'
    Assert-Report $reportEvidence.value $Current
    Assert-Binding $bindingEvidence.value $reportEvidence.digest.sha256 `
        $reportEvidence.value $Current
    Assert-Commit $commitEvidence.value $reportEvidence.digest.sha256 `
        $bindingEvidence.digest.sha256 $reportEvidence.value
    foreach ($evidence in @($reportEvidence,$bindingEvidence,$commitEvidence)) {
        $after = Get-StableFileDigest $evidence.digest.path
        if ($after.sha256 -cne $evidence.digest.sha256 -or
                $after.size -ne $evidence.digest.size -or
                $after.last_write_utc -ne $evidence.digest.last_write_utc) {
            throw 'SERVER_VERSION_MATRIX_EVIDENCE_CHANGED_DURING_VALIDATION'
        }
    }
    return $reportEvidence.value
}

function Get-LatestCompleteEvidenceReport {
    if (-not (Test-Path -LiteralPath $evidenceRunsRoot -PathType Container)) { return $null }
    $root = Assert-DirectLocalPath $evidenceRunsRoot -Directory
    $candidates = [Collections.Generic.List[string]]::new()
    foreach ($entry in @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not $entry.PSIsContainer) {
            throw "SERVER_VERSION_MATRIX_EVIDENCE_RUN_ENTRY_INVALID|$($entry.Name)"
        }
        if ($entry.Name.StartsWith('.staging-', [StringComparison]::Ordinal)) {
            throw "SERVER_VERSION_MATRIX_PENDING_STAGING_REJECTED|$($entry.Name)"
        }
        if ($entry.Name -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{7}Z$') {
            throw "SERVER_VERSION_MATRIX_EVIDENCE_RUN_NAME_INVALID|$($entry.Name)"
        }
        $null = Assert-ExactEvidenceDirectory $entry.FullName
        [void]$candidates.Add([string]$entry.Name)
    }
    if ($candidates.Count -eq 0) { return $null }
    $ordered = [string[]]$candidates.ToArray()
    [Array]::Sort($ordered, [StringComparer]::Ordinal)
    [Array]::Reverse($ordered)
    return Join-Path (Join-Path $root $ordered[0]) 'report.json'
}

function Write-NewFileBytes([string]$Path, [byte[]]$Bytes) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
}

function ConvertTo-RepositoryRelative([string]$Path) {
    $full = Assert-PathBelow $repoRoot ([IO.Path]::GetFullPath($Path)) 'repository-relative'
    $relative = $full.Substring($repoRoot.TrimEnd([char[]]@('\','/')).Length + 1).Replace('\','/')
    Assert-CanonicalRelative $relative 'repository-relative'
    return $relative
}

function New-EvidenceTriplet {
    param(
        [Parameter(Mandatory)][object]$Current,
        [Parameter(Mandatory)][object[]]$Cases
    )
    if ($Cases.Count -ne 12) { throw 'SERVER_VERSION_MATRIX_COMPLETE_12_OF_12_REQUIRED' }
    $generatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    $report = [pscustomobject][ordered]@{
        schema = $reportSchema
        generated_at = $generatedAt
        source_mode = 'EXECUTED'
        target_versions = @($targetVersions)
        expected_case_count = 12
        observed_case_count = 12
        stable_case_count = 10
        beta_case_count = 2
        all_cases_passed = $true
        cleanup_all_zero = $true
        cases = @($Cases)
    }
    $reportBytes = ConvertTo-CompactJsonBytes $report
    Assert-SanitizedEvidenceBytes $reportBytes 'new-report'
    $reportSha256 = Get-BytesSha256 $reportBytes
    $currentBytes = ConvertTo-CompactJsonBytes $Current.public
    $binding = [pscustomobject][ordered]@{
        schema = $bindingSchema
        generated_at = $generatedAt
        report_schema = $reportSchema
        report_generated_at = $generatedAt
        report_sha256 = $reportSha256
        source_mode = 'EXECUTED'
        current_sha256 = Get-BytesSha256 $currentBytes
        current = $Current.public
        passed = $true
    }
    $bindingBytes = ConvertTo-CompactJsonBytes $binding
    Assert-SanitizedEvidenceBytes $bindingBytes 'new-binding'
    $bindingSha256 = Get-BytesSha256 $bindingBytes
    $commit = [pscustomobject][ordered]@{
        schema = $commitSchema
        generated_at = $generatedAt
        report_schema = $reportSchema
        binding_schema = $bindingSchema
        report_sha256 = $reportSha256
        binding_sha256 = $bindingSha256
        committed = $true
    }
    $commitBytes = ConvertTo-CompactJsonBytes $commit
    Assert-SanitizedEvidenceBytes $commitBytes 'new-commit'

    $runName = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH-mm-ss-fffffffZ')
    $finalRoot = Join-Path $evidenceRunsRoot $runName
    $stagingRoot = Join-Path $evidenceRunsRoot (
        '.staging-' + $runName + '-' + [IO.Path]::GetRandomFileName())
    if ((Test-Path -LiteralPath $finalRoot) -or (Test-Path -LiteralPath $stagingRoot)) {
        throw 'SERVER_VERSION_MATRIX_EVIDENCE_RUN_COLLISION'
    }
    [void][IO.Directory]::CreateDirectory($stagingRoot)
    try {
        $stagingReport = Join-Path $stagingRoot 'report.json'
        Write-NewFileBytes $stagingReport $reportBytes
        Write-NewFileBytes (Join-Path $stagingRoot 'binding.json') $bindingBytes
        # The commit marker is the last staged write; publication is one same-volume rename.
        Write-NewFileBytes (Join-Path $stagingRoot 'commit.json') $commitBytes
        $null = Assert-EvidenceTriplet $stagingReport $Current -AllowStaging
        [IO.Directory]::Move($stagingRoot, $finalRoot)
        $finalReport = Join-Path $finalRoot 'report.json'
        $null = Assert-EvidenceTriplet $finalReport $Current
        return $finalReport
    } finally {
        if (Test-Path -LiteralPath $stagingRoot -PathType Container) {
            foreach ($name in @('report.json','binding.json','commit.json')) {
                $candidate = Join-Path $stagingRoot $name
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    [IO.File]::Delete((Assert-DirectLocalPath $candidate))
                }
            }
            [IO.Directory]::Delete((Assert-DirectLocalPath $stagingRoot -Directory), $false)
        }
    }
}

function Initialize-ExecuteDirectories {
    foreach ($directory in @($workRoot,$invocationRoot,$evidenceRunsRoot)) {
        if (Test-Path -LiteralPath $directory) {
            $null = Assert-DirectLocalPath $directory -Directory
        } else {
            $null = Assert-ExistingOrParentDirect $directory
            [void][IO.Directory]::CreateDirectory($directory)
            $null = Assert-DirectLocalPath $directory -Directory
        }
    }
}

function Open-ExecutionLock {
    try {
        return [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch {
        throw 'SERVER_VERSION_MATRIX_EXECUTION_ALREADY_ACTIVE'
    }
}

function Assert-NoActiveExecution {
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) { return }
    $resolved = Assert-DirectLocalPath $lockPath
    try {
        $probe = [IO.File]::Open($resolved, [IO.FileMode]::Open,
            [IO.FileAccess]::Read, [IO.FileShare]::None)
        $probe.Dispose()
    } catch {
        throw 'SERVER_VERSION_MATRIX_EXECUTION_ALREADY_ACTIVE'
    }
}

function Clear-ExecutionCheckpoint {
    if (Test-Path -LiteralPath $checkpointPath -PathType Leaf) {
        [IO.File]::Delete((Assert-DirectLocalPath $checkpointPath))
    }
}

function Write-ExecutionCheckpoint {
    param(
        [Parameter(Mandatory)][object]$Current,
        [Parameter(Mandatory)][object[]]$Cases
    )
    $checkpoint = [pscustomobject][ordered]@{
        schema = $checkpointSchema
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        current_sha256 = Get-BytesSha256 (ConvertTo-CompactJsonBytes $Current.public)
        case_count = @($Cases).Count
        cases = @($Cases)
    }
    $bytes = ConvertTo-CompactJsonBytes $checkpoint
    Assert-SanitizedEvidenceBytes $bytes 'checkpoint'
    $tempPath = Join-Path $workRoot ('.checkpoint-' + [IO.Path]::GetRandomFileName())
    $backupPath = Join-Path $workRoot ('.checkpoint-backup-' + [IO.Path]::GetRandomFileName())
    try {
        Write-NewFileBytes $tempPath $bytes
        if (Test-Path -LiteralPath $checkpointPath -PathType Leaf) {
            [IO.File]::Replace(
                (Assert-DirectLocalPath $tempPath),
                (Assert-DirectLocalPath $checkpointPath),
                $backupPath,
                $true)
        } else {
            [IO.File]::Move(
                (Assert-DirectLocalPath $tempPath),
                $checkpointPath)
        }
    } finally {
        if (Test-Path -LiteralPath $tempPath -PathType Leaf) {
            [IO.File]::Delete((Assert-DirectLocalPath $tempPath))
        }
        if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
            [IO.File]::Delete((Assert-DirectLocalPath $backupPath))
        }
    }
}

function Read-ExecutionCheckpoint([object]$Current) {
    if (-not (Test-Path -LiteralPath $checkpointPath -PathType Leaf)) {
        return @()
    }
    $evidence = Read-StableJson $checkpointPath
    $value = $evidence.value
    if (-not (Test-ExactProperties $value @('schema','generated_at','current_sha256',
            'case_count','cases')) -or
            [string]$value.schema -cne $checkpointSchema -or
            [int]$value.case_count -lt 0 -or [int]$value.case_count -gt 12 -or
            @($value.cases).Count -ne [int]$value.case_count) {
        throw 'SERVER_VERSION_MATRIX_CHECKPOINT_INVALID'
    }
    $currentSha256 = Get-BytesSha256 (ConvertTo-CompactJsonBytes $Current.public)
    if ([string]$value.current_sha256 -cne $currentSha256) {
        throw 'SERVER_VERSION_MATRIX_CHECKPOINT_SOURCE_MISMATCH'
    }
    return @($value.cases)
}

if ([bool]$Execute -eq [bool]$ReportOnly) {
    throw 'SERVER_VERSION_MATRIX_EXPLICIT_MODE_REQUIRED|specify exactly one of -Execute or -ReportOnly'
}
if ($Resume -and -not $Execute) {
    throw 'SERVER_VERSION_MATRIX_RESUME_EXECUTE_REQUIRED|specify -Execute with -Resume'
}

if ($ReportOnly) {
    Assert-NoActiveExecution
    $current = Get-CurrentBinding
    $latest = Get-LatestCompleteEvidenceReport
    if ($null -eq $latest) { throw 'SERVER_VERSION_MATRIX_COMMITTED_EVIDENCE_REQUIRED' }
    $null = Assert-EvidenceTriplet $latest $current
    Write-Output "SERVER_VERSION_PROCESS_MATRIX_REPORT_ONLY_PASS|$(ConvertTo-RepositoryRelative $latest)"
    exit 0
}

Initialize-ExecuteDirectories
$lock = Open-ExecutionLock
try {
    if (@(Get-ChildItem -LiteralPath $evidenceRunsRoot -Directory -Force |
            Where-Object { $_.Name.StartsWith('.staging-', [StringComparison]::Ordinal) }).Count -ne 0) {
        throw 'SERVER_VERSION_MATRIX_PENDING_STAGING_REJECTED'
    }
    $tooling = [pscustomobject]@{
        jdk21 = Resolve-CachedJdk 21
        gradle = Resolve-CachedGradle961
    }
    if (-not $Resume) {
        Clear-ExecutionCheckpoint
    }
    Invoke-ProductBuild $tooling
    $currentBefore = Get-CurrentBinding
    $checkpointCases = if ($Resume) {
        @(Read-ExecutionCheckpoint $currentBefore)
    } else { @() }
    $cases = [Collections.Generic.List[object]]::new()
    $ordinal = 1
    foreach ($definition in $currentBefore.definitions) {
        $saved = @($checkpointCases | Where-Object {
            [string]$_.case_id -ceq [string]$definition.case_id
        })
        if ($saved.Count -gt 1) {
            throw "SERVER_VERSION_MATRIX_CHECKPOINT_DUPLICATE|$($definition.case_id)"
        }
        if ($saved.Count -eq 1) {
            Assert-CaseBinding $saved[0] $definition $currentBefore
            [void]$cases.Add($saved[0])
            Write-Output "SERVER_VERSION_MATRIX_RESUME_SKIP|$($definition.case_id)"
        } else {
            $invocation = Invoke-MatrixCase $definition $currentBefore $ordinal
            [void]$cases.Add($invocation.case)
            Write-ExecutionCheckpoint $currentBefore $cases.ToArray()
        }
        $ordinal++
    }
    if ($cases.Count -ne 12) { throw 'SERVER_VERSION_MATRIX_COMPLETE_12_OF_12_REQUIRED' }
    $currentAfter = Get-CurrentBinding
    Compare-PublicBinding $currentBefore.public $currentAfter.public
    $published = New-EvidenceTriplet $currentAfter $cases.ToArray()
    Clear-ExecutionCheckpoint
    Write-Output "SERVER_VERSION_PROCESS_MATRIX_PASS|$(ConvertTo-RepositoryRelative $published)"
} finally {
    if ($null -ne $lock) { $lock.Dispose() }
    if (Test-Path -LiteralPath $lockPath -PathType Leaf) {
        [IO.File]::Delete((Assert-DirectLocalPath $lockPath))
    }
}
