[CmdletBinding()]
param(
    [switch]$Execute,
    [switch]$ReportOnly,
    [switch]$Resume,
    [ValidateRange(1, 10080)]
    [int]$MaximumReportAgeMinutes = 1440,
    [string]$ExpectedSourceCommit = $env:MCACE_ARTIFACT_SOURCE_COMMIT,
    [string]$ReleaseBundleRoot = $env:MCACE_MATRIX_RELEASE_BUNDLE_ROOT,
    [string]$SupervisorTrustRootPath = $env:MCACE_MATRIX_SUPERVISOR_TRUST_ROOT_PATH,
    [string]$ExpectedSupervisorTrustRootSha256 = $env:MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256,
    [string]$SupervisorExchangeRoot = $env:MCACE_MATRIX_SUPERVISOR_EXCHANGE_ROOT,
    [ValidateRange(1, 1800)]
    [int]$SupervisorReceiptWaitSeconds = 300,
    [string]$ProductVersion = '0.0.1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop

$reportSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V4'
$bindingSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_BINDING_V4'
$commitSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_COMMIT_V4'
$rawManifestSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_MANIFEST_V1'
$signingRequestSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_SIGNING_REQUEST_V1'
$receiptSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_RECEIPT_V1'
$trustRootSchema = 'MCACE_SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_V1'
$rawSetDomain = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_SET_V1'
$caseRuntimeDomain = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_CASE_RUNTIME_SET_V1'
$releaseArtifactDomain = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_RELEASE_ARTIFACT_SET_V1'
$matrixProductDomain = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_PRODUCT_JAR_SET_V1'
# These names are retained only as an explicit terminal legacy deny-list.  No
# V2/V3 document is generated or accepted by this producer.
$obsoleteEvidenceSchemas = @(
    'MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V2',
    'MCACE_SERVER_VERSION_PROCESS_MATRIX_BINDING_V2',
    'MCACE_SERVER_VERSION_PROCESS_MATRIX_COMMIT_V2',
    'MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V3',
    'MCACE_SERVER_VERSION_PROCESS_MATRIX_BINDING_V3',
    'MCACE_SERVER_VERSION_PROCESS_MATRIX_COMMIT_V3')
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
$checkpointSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_CHECKPOINT_V2'

$productJarRelatives = [ordered]@{
    velocity = "mcace-server-velocity/build/libs/mcace-server-velocity-$ProductVersion.jar"
    bungee = "mcace-server-bungeecord/build/libs/mcace-server-bungeecord-$ProductVersion.jar"
    paper = "mcace-server-paper/build/libs/mcace-server-paper-$ProductVersion.jar"
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

function Invoke-ExactGit([string[]]$Arguments, [string]$FailureCode) {
    $oldErrorActionPreference = $ErrorActionPreference
    $exitCode = $null
    $output = @()
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& git -C $repoRoot @Arguments 2>&1 | ForEach-Object { $_.ToString() })
        $exitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $oldErrorActionPreference }
    if ($null -eq $exitCode -or $exitCode -ne 0) {
        throw "$FailureCode|exit=$exitCode"
    }
    return (($output -join "`n").Trim())
}

function Assert-ExactGitSourceIdentity {
    if ($ExpectedSourceCommit -cnotmatch '^[0-9a-f]{40}$') {
        throw 'SERVER_VERSION_MATRIX_SOURCE_COMMIT_REQUIRED'
    }
    if ($ProductVersion -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') {
        throw 'SERVER_VERSION_MATRIX_PRODUCT_VERSION_INVALID'
    }
    $null = Invoke-ExactGit @('cat-file','-e',"$ExpectedSourceCommit^{commit}") `
        'SERVER_VERSION_MATRIX_SOURCE_COMMIT_UNKNOWN'
    $head = Invoke-ExactGit @('rev-parse','--verify','HEAD') `
        'SERVER_VERSION_MATRIX_SOURCE_HEAD_UNAVAILABLE'
    if ($head -cne $ExpectedSourceCommit) {
        throw "SERVER_VERSION_MATRIX_SOURCE_HEAD_MISMATCH|expected=$ExpectedSourceCommit|actual=$head"
    }
    $status = Invoke-ExactGit @('status','--porcelain=v1','--untracked-files=all') `
        'SERVER_VERSION_MATRIX_SOURCE_STATUS_FAILED'
    if (-not [string]::IsNullOrEmpty($status)) {
        throw 'SERVER_VERSION_MATRIX_SOURCE_WORKTREE_DIRTY'
    }
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
    Assert-ExactGitSourceIdentity
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
        source_commit = $ExpectedSourceCommit
        product_version = $ProductVersion
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

function Get-OrderedRawReportSetSha256([object[]]$Descriptors) {
    $records = @($Descriptors | ForEach-Object {
        [pscustomobject][ordered]@{
            ordinal = [int]$_.ordinal
            case_id = [string]$_.case_id
            path = [string]$_.path
            sha256 = [string]$_.sha256
            size_bytes = [long]$_.size_bytes
        }
    })
    return Get-BytesSha256 (ConvertTo-CompactJsonBytes ([pscustomobject][ordered]@{
        domain = $rawSetDomain
        source_commit = $ExpectedSourceCommit
        reports = $records
    }))
}

function Get-SetSha256([string]$Domain, [object]$Value) {
    return Get-BytesSha256 (ConvertTo-CompactJsonBytes ([pscustomobject][ordered]@{
        domain=$Domain; value=$Value
    }))
}

function Test-FullPathBelow([string]$Root, [string]$Candidate) {
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd([char[]]@('\','/')) +
        [IO.Path]::DirectorySeparatorChar
    $candidateFull = [IO.Path]::GetFullPath($Candidate)
    $comparison = if ([IO.Path]::DirectorySeparatorChar -eq '\') {
        [StringComparison]::OrdinalIgnoreCase
    } else { [StringComparison]::Ordinal }
    return $candidateFull.StartsWith($prefix, $comparison)
}

function Assert-OutOfBandDirectory([string]$Path, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "SERVER_VERSION_MATRIX_${Label}_REQUIRED"
    }
    $full = [IO.Path]::GetFullPath($Path)
    if (Test-FullPathBelow $repoRoot $full) {
        throw "SERVER_VERSION_MATRIX_${Label}_MUST_BE_OUT_OF_REPO"
    }
    if (-not (Test-Path -LiteralPath $full)) {
        $null = Assert-ExistingOrParentDirect $full
        [void][IO.Directory]::CreateDirectory($full)
    }
    return Assert-DirectLocalPath $full -Directory
}

function Read-MatrixSupervisorTrustRoot {
    if ($ExpectedSupervisorTrustRootSha256 -cnotmatch '^[0-9a-fA-F]{64}$') {
        throw 'SERVER_VERSION_MATRIX_APPROVED_SUPERVISOR_PIN_REQUIRED'
    }
    $approved = [Environment]::GetEnvironmentVariable(
        'MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256','Process')
    if ($approved -cnotmatch '^[0-9a-fA-F]{64}$' -or
            $approved.ToLowerInvariant() -cne $ExpectedSupervisorTrustRootSha256.ToLowerInvariant()) {
        throw 'SERVER_VERSION_MATRIX_SUPERVISOR_PIN_NOT_APPROVED'
    }
    if ([string]::IsNullOrWhiteSpace($SupervisorTrustRootPath)) {
        throw 'SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_REQUIRED'
    }
    $path = [IO.Path]::GetFullPath($SupervisorTrustRootPath)
    if (Test-FullPathBelow $repoRoot $path) {
        throw 'SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_MUST_BE_OUT_OF_REPO'
    }
    if (-not [string]::IsNullOrWhiteSpace($ReleaseBundleRoot) -and
            (Test-FullPathBelow ([IO.Path]::GetFullPath($ReleaseBundleRoot)) $path)) {
        throw 'SERVER_VERSION_MATRIX_SELF_SUPERVISOR_TRUST_ROOT_REJECTED'
    }
    if (-not [string]::IsNullOrWhiteSpace($SupervisorExchangeRoot) -and
            (Test-FullPathBelow ([IO.Path]::GetFullPath($SupervisorExchangeRoot)) $path)) {
        throw 'SERVER_VERSION_MATRIX_SELF_SUPERVISOR_TRUST_ROOT_REJECTED'
    }
    $document = Read-StableJson $path
    if ([string]$document.digest.sha256 -cne $approved.ToLowerInvariant()) {
        throw 'SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_PIN_MISMATCH'
    }
    $root = $document.value
    if (-not (Test-ExactProperties $root @('schema','artifact_class','key_id','algorithm',
            'modulus_base64','exponent_base64','test_fixture')) -or
            [string]$root.schema -cne $trustRootSchema -or
            [string]$root.artifact_class -cne 'OUT_OF_BAND_PINNED_MATRIX_SUPERVISOR_TRUST_ROOT' -or
            [string]$root.key_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$' -or
            [string]$root.algorithm -cne 'RSA_PKCS1_SHA256' -or
            -not (Test-JsonBoolean $root.test_fixture) -or [bool]$root.test_fixture) {
        throw 'SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_INVALID'
    }
    try {
        $modulus = [Convert]::FromBase64String([string]$root.modulus_base64)
        $exponent = [Convert]::FromBase64String([string]$root.exponent_base64)
    } catch { throw 'SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_KEY_ENCODING_INVALID' }
    if ($modulus.Length -lt 256 -or $modulus.Length -gt 512 -or
            $exponent.Length -lt 1 -or $exponent.Length -gt 4) {
        throw 'SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_KEY_SIZE_INVALID'
    }
    return [pscustomobject]@{
        evidence=$document; value=$root; modulus=$modulus; exponent=$exponent
    }
}

function Assert-ServerReleaseJar([string]$Path, [string]$FileName) {
    $marker = [ordered]@{
        'mcace-server-velocity.jar'='com/ellan/mcace/velocity/MCAceVelocityPlugin.class'
        'mcace-server-bungeecord.jar'='com/ellan/mcace/bungeecord/MCAceBungeePlugin.class'
        'mcace-server-paper.jar'='com/ellan/mcace/paper/MCAcePaperPlugin.class'
    }
    if (-not $marker.Contains($FileName)) { return }
    $stream = [IO.File]::Open((Assert-DirectLocalPath $Path), [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream,[IO.Compression.ZipArchiveMode]::Read,$false)
        try {
            $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($entry in $archive.Entries) {
                if ([string]::IsNullOrWhiteSpace([string]$entry.FullName) -or
                        [string]$entry.FullName -match '(^|/)\.\.?(?:/|$)' -or
                        -not $names.Add([string]$entry.FullName)) {
                    throw "SERVER_VERSION_MATRIX_RELEASE_JAR_ENTRY_INVALID|$FileName"
                }
            }
            if (-not $names.Contains([string]$marker[$FileName])) {
                throw "SERVER_VERSION_MATRIX_RELEASE_JAR_MARKER_MISSING|$FileName"
            }
        } finally { $archive.Dispose() }
    } finally { $stream.Dispose() }
}

function Read-ReleaseBundleSnapshot {
    if ([string]::IsNullOrWhiteSpace($ReleaseBundleRoot)) {
        throw 'SERVER_VERSION_MATRIX_RELEASE_BUNDLE_ROOT_REQUIRED'
    }
    $root = Assert-DirectLocalPath ([IO.Path]::GetFullPath($ReleaseBundleRoot)) -Directory
    $jarNames = @('mcace-client-fabric-1.21.11.jar','mcace-client-fabric-26.1.2.jar',
        'mcace-client-fabric-26.2.jar','mcace-server-velocity.jar',
        'mcace-server-bungeecord.jar','mcace-server-paper.jar')
    $expectedNames = @('SHA256SUMS','release-manifest.properties') + $jarNames
    $entries = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
    if ($entries.Count -ne 8 -or
            ((@($entries.Name | Sort-Object) -join '|') -cne
                (($expectedNames | Sort-Object) -join '|')) -or
            @($entries | Where-Object { $_.PSIsContainer -or
                ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count -ne 0) {
        throw 'SERVER_VERSION_MATRIX_RELEASE_BUNDLE_FILE_SET_INVALID'
    }
    $manifestDigest = Get-StableFileDigest (Join-Path $root 'release-manifest.properties')
    $sumsDigest = Get-StableFileDigest (Join-Path $root 'SHA256SUMS')
    $manifestRaw = [IO.File]::ReadAllText($manifestDigest.path,[Text.UTF8Encoding]::new($false,$true))
    $sumsRaw = [IO.File]::ReadAllText($sumsDigest.path,[Text.UTF8Encoding]::new($false,$true))
    if ($manifestRaw.Contains("`r") -or -not $manifestRaw.EndsWith("`n") -or
            $sumsRaw.Contains("`r") -or -not $sumsRaw.EndsWith("`n")) {
        throw 'SERVER_VERSION_MATRIX_RELEASE_BUNDLE_ENCODING_INVALID'
    }
    $manifest = [ordered]@{}
    foreach ($line in @($manifestRaw.TrimEnd("`n") -split "`n")) {
        $separator = $line.IndexOf('=')
        if ($separator -lt 1) { throw 'SERVER_VERSION_MATRIX_RELEASE_MANIFEST_INVALID' }
        $key = $line.Substring(0,$separator); $value = $line.Substring($separator+1)
        if ($manifest.Contains($key)) { throw 'SERVER_VERSION_MATRIX_RELEASE_MANIFEST_DUPLICATE' }
        $manifest[$key] = $value
    }
    if ([string]$manifest.schema -cne 'MCACE_RELEASE_BUNDLE_V4' -or
            [string]$manifest.bundle_profile -cne 'RELEASE' -or
            [string]$manifest.release_identity -cne 'true' -or
            [string]$manifest.deployable_count -cne '6' -or
            [string]$manifest.bundle_entry_count -cne '8' -or
            [string]$manifest.product_version -cne $ProductVersion -or
            [string]$manifest.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
            [string]$manifest.artifact_source_commit -cne $ExpectedSourceCommit) {
        throw 'SERVER_VERSION_MATRIX_RELEASE_MANIFEST_INVALID'
    }
    $sumLines = @($sumsRaw.TrimEnd("`n") -split "`n")
    if ($sumLines.Count -ne 6) { throw 'SERVER_VERSION_MATRIX_RELEASE_SHA256SUMS_INVALID' }
    $artifacts = [Collections.Generic.List[object]]::new()
    $byName = [ordered]@{}
    foreach ($line in $sumLines) {
        if ($line -cnotmatch '^(?<sha>[0-9a-f]{64})  (?<file>[A-Za-z0-9][A-Za-z0-9._-]*\.jar)$' -or
                [string]$Matches.file -cnotin $jarNames -or $byName.Contains([string]$Matches.file)) {
            throw 'SERVER_VERSION_MATRIX_RELEASE_SHA256SUMS_INVALID'
        }
        $fileName=[string]$Matches.file; $digest=Get-StableFileDigest (Join-Path $root $fileName)
        $key=$fileName.Remove($fileName.Length-4).Replace('-','_').Replace('.','_')
        if ([string]$digest.sha256 -cne [string]$Matches.sha -or
                [string]$manifest["artifact.$key.file"] -cne $fileName -or
                [string]$manifest["artifact.$key.sha256"] -cne [string]$digest.sha256) {
            throw "SERVER_VERSION_MATRIX_RELEASE_ARTIFACT_BINDING_INVALID|$fileName"
        }
        Assert-ServerReleaseJar $digest.path $fileName
        $descriptor=[pscustomobject][ordered]@{
            file=$fileName; sha256=[string]$digest.sha256; size_bytes=[long]$digest.size
        }
        $byName[$fileName]=$descriptor; [void]$artifacts.Add($descriptor)
    }
    $artifactValues=@($artifacts.ToArray() | Sort-Object file)
    return [pscustomobject]@{
        root=$root; schema='MCACE_RELEASE_BUNDLE_V4'
        release_source_commit=[string]$manifest.source_commit
        artifact_source_commit=[string]$manifest.artifact_source_commit
        manifest_sha256=[string]$manifestDigest.sha256; manifest_bytes=[long]$manifestDigest.size
        sha256s_sha256=[string]$sumsDigest.sha256; sha256s_bytes=[long]$sumsDigest.size
        artifacts=$artifactValues; by_name=[pscustomobject]$byName
        artifact_set_sha256=Get-SetSha256 $releaseArtifactDomain $artifactValues
    }
}

function Get-MatrixProductCommitment([object]$Current, [object]$Bundle) {
    $map=[ordered]@{ velocity='mcace-server-velocity.jar'; bungee='mcace-server-bungeecord.jar'; paper='mcace-server-paper.jar' }
    $values=[Collections.Generic.List[object]]::new()
    foreach ($pair in $map.GetEnumerator()) {
        $matrix=$Current.public.product_jars.([string]$pair.Key)
        $release=$Bundle.by_name.([string]$pair.Value)
        if ([string]$matrix.sha256 -cne [string]$release.sha256 -or
                [long]$matrix.size -ne [long]$release.size_bytes) {
            throw "SERVER_VERSION_MATRIX_RELEASE_PRODUCT_CROSS_BINDING_INVALID|$($pair.Key)"
        }
        [void]$values.Add([pscustomobject][ordered]@{
            role=[string]$pair.Key; bundle_file=[string]$pair.Value
            matrix_relative=[string]$matrix.relative; sha256=[string]$matrix.sha256
            size_bytes=[long]$matrix.size
        })
    }
    return [pscustomobject]@{
        values=$values.ToArray(); count=3
        sha256=Get-SetSha256 $matrixProductDomain $values.ToArray()
    }
}

$matrixReceiptPropertyNames = @(
    'schema','artifact_class','source_mode','signed_at','expires_at',
    'release_source_commit','artifact_source_commit','product_version',
    'operation_attempt_id','challenge_nonce','challenge_issued_at',
    'report_sha256','report_size_bytes','binding_sha256','binding_size_bytes',
    'raw_manifest_sha256','raw_manifest_size_bytes','ordered_raw_report_set_sha256',
    'case_runtime_commitment_sha256','case_count','process_identity_count',
    'release_bundle_schema','release_bundle_manifest_sha256',
    'release_bundle_manifest_size_bytes','release_bundle_sha256s_sha256',
    'release_bundle_sha256s_size_bytes','release_bundle_artifact_set_sha256',
    'release_bundle_artifact_count','matrix_product_jar_set_sha256',
    'matrix_product_jar_count','supervisor_independent','signer_key_id',
    'signer_trust_root_sha256','signature_algorithm','test_fixture','signature_base64')

function Get-MatrixReceiptSigningPayload([object]$Receipt) {
    $lines=[Collections.Generic.List[string]]::new()
    [void]$lines.Add('MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_RECEIPT_SIGNING_V1')
    foreach($name in @($matrixReceiptPropertyNames | Where-Object { $_ -cne 'signature_base64' })) {
        $value=$Receipt.$name
        if($value -is [bool]){$rendered=if([bool]$value){'true'}else{'false'}}
        elseif(Test-JsonInteger $value){$rendered=[Convert]::ToString($value,[Globalization.CultureInfo]::InvariantCulture)}
        else{$rendered=[string]$value}
        if($rendered -match '[\r\n]'){throw 'SERVER_VERSION_MATRIX_SUPERVISOR_SIGNING_VALUE_INVALID'}
        [void]$lines.Add("$name=$rendered")
    }
    return [Text.UTF8Encoding]::new($false).GetBytes(($lines -join "`n")+"`n")
}

function Test-RsaPkcs1Sha256Signature([byte[]]$Payload,[byte[]]$Signature,[byte[]]$Modulus,[byte[]]$Exponent) {
    $rsa=[Security.Cryptography.RSACryptoServiceProvider]::new()
    try{$rsa.PersistKeyInCsp=$false;$rsa.ImportParameters([Security.Cryptography.RSAParameters]@{Modulus=$Modulus;Exponent=$Exponent});return $rsa.VerifyData($Payload,'SHA256',$Signature)}
    finally{$rsa.Dispose()}
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
        $allArguments = @($Arguments) + @(
            "-PmcaceSourceCommit=$ExpectedSourceCommit",
            "-PmcaceArtifactSourceCommit=$ExpectedSourceCommit",
            "-PmcaceProductVersion=$ProductVersion") + @(Get-StrictGradleFlags) + @(
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
        [string]$InvocationLogSha256,
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
            }).Count -ne 0 -or @($cleanupIds | Select-Object -Unique).Count -ne $cleanupIds.Count) {
        throw "SERVER_VERSION_MATRIX_RAW_CLEANUP_IDS_INVALID|$($Definition.case_id)"
    }
    if ([string]::IsNullOrWhiteSpace($InvocationLogSha256)) {
        if ($ReportOnlyValidation) { $InvocationLogSha256 = ('0' * 64) }
        else { throw "SERVER_VERSION_MATRIX_INVOCATION_LOG_HASH_REQUIRED|$($Definition.case_id)" }
    }
    if ($InvocationLogSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "SERVER_VERSION_MATRIX_INVOCATION_LOG_HASH_INVALID|$($Definition.case_id)"
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
        execution_mode = 'EXECUTE'
        invocation_exit_code = 0
        invocation_log_sha256 = $InvocationLogSha256
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
        process_cleanup_observed = $true
        passed = $true
    }
}

function Assert-PackagedRawReport {
    param(
        [Parameter(Mandatory)][object]$Raw,
        [Parameter(Mandatory)][object]$Case,
        [Parameter(Mandatory)][object]$Definition
    )
    $names = @(
        'schema','proxy','backend_platform','backend_minecraft_version','forwarding_mode',
        'forwarding_configured','proxy_port','backend_port','tcp_connected','login_success',
        'compression_seen','configuration_finished','mcace_server_hello','mcace_auth_result',
        'mcace_auth_accepted','backend_admission','backend_context_shadow_audit','channels',
        'packet_trace','limitations','cleanup_process_ids','remaining_run_processes')
    $forwarding = if ($Definition.proxy -ceq 'VELOCITY') {
        'velocity-modern'
    } else { 'bungee-ip-forwarding' }
    if (-not (Test-ExactProperties $Raw $names) -or
            -not (Test-JsonInteger $Raw.schema) -or [int]$Raw.schema -ne 4 -or
            [string]$Raw.proxy -cne [string]$Definition.proxy -or
            [string]$Raw.backend_platform -cne [string]$Definition.backend -or
            [string]$Raw.backend_minecraft_version -cne [string]$Definition.minecraft_version -or
            [string]$Raw.forwarding_mode -cne $forwarding -or
            -not (Test-JsonInteger $Raw.proxy_port) -or [int]$Raw.proxy_port -lt 1 -or
            [int]$Raw.proxy_port -gt 65535 -or -not (Test-JsonInteger $Raw.backend_port) -or
            [int]$Raw.backend_port -lt 1 -or [int]$Raw.backend_port -gt 65535 -or
            [int]$Raw.proxy_port -eq [int]$Raw.backend_port) {
        throw "SERVER_VERSION_MATRIX_PACKAGED_RAW_IDENTITY_INVALID|$($Definition.case_id)"
    }
    foreach ($name in @('forwarding_configured','tcp_connected','login_success',
            'compression_seen','configuration_finished','mcace_server_hello','mcace_auth_result',
            'mcace_auth_accepted','backend_admission','backend_context_shadow_audit')) {
        if (-not (Test-JsonBoolean $Raw.$name) -or -not [bool]$Raw.$name) {
            throw "SERVER_VERSION_MATRIX_PACKAGED_RAW_ASSERTION_FAILED|$($Definition.case_id)|$name"
        }
    }
    $cleanupIds = @($Raw.cleanup_process_ids)
    if (@($Raw.limitations).Count -ne 0 -or @($Raw.remaining_run_processes).Count -ne 0 -or
            $cleanupIds.Count -lt 2 -or @($cleanupIds | Where-Object {
                -not (Test-JsonInteger $_) -or [long]$_ -le 0
            }).Count -ne 0 -or @($cleanupIds | Select-Object -Unique).Count -ne $cleanupIds.Count -or
            $cleanupIds.Count -ne [int]$Case.cleanup_process_count) {
        throw "SERVER_VERSION_MATRIX_PACKAGED_RAW_CLEANUP_INVALID|$($Definition.case_id)"
    }
    $expectedPlay = if ($Definition.minecraft_version -ceq '1.21.11') { '0x30' } else { '0x31' }
    if (@($Raw.channels | Where-Object { [string]$_ -ceq 'mcace:handshake' }).Count -lt 1 -or
            @($Raw.packet_trace | Where-Object { [string]$_ -ceq "PLAY:$expectedPlay" }).Count -ne 1) {
        throw "SERVER_VERSION_MATRIX_PACKAGED_RAW_PROTOCOL_INVALID|$($Definition.case_id)"
    }
}

function Assert-RawManifest {
    param(
        [Parameter(Mandatory)][object]$ManifestEvidence,
        [Parameter(Mandatory)][object]$Report,
        [Parameter(Mandatory)][object]$Current,
        [Parameter(Mandatory)][string]$EvidenceDirectory
    )
    $manifest = $ManifestEvidence.value
    $names = @('schema','generated_at','source_mode','source_commit','product_version',
        'case_count','ordered_raw_report_set_sha256','reports')
    if (-not (Test-ExactProperties $manifest $names) -or
            [string]$manifest.schema -cne $rawManifestSchema -or
            [string]$manifest.source_mode -cne 'EXECUTED' -or
            [string]$manifest.source_commit -cne $ExpectedSourceCommit -or
            [string]$manifest.product_version -cne $ProductVersion -or
            -not (Test-JsonInteger $manifest.case_count) -or [int]$manifest.case_count -ne 12 -or
            [string]$manifest.ordered_raw_report_set_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            @($manifest.reports).Count -ne 12 -or
            -not (Test-ExactDateTimeOffsetInstant $manifest.generated_at $Report.generated_at `
                'raw-manifest.generated_at')) {
        throw 'SERVER_VERSION_MATRIX_RAW_MANIFEST_INVALID'
    }
    $rawRoot = Assert-DirectLocalPath (Join-Path $EvidenceDirectory 'raw') -Directory
    $entries = @(Get-ChildItem -LiteralPath $rawRoot -Force -ErrorAction Stop)
    if ($entries.Count -ne 12 -or @($entries | Where-Object {
                $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
            }).Count -ne 0) {
        throw 'SERVER_VERSION_MATRIX_RAW_REPORT_SET_INVALID'
    }
    $descriptors = @($manifest.reports)
    $cases = @($Report.cases)
    $descriptorNames = @('ordinal','case_id','path','sha256','size_bytes','raw_schema',
        'minecraft_version','backend','proxy','execution_mode','invocation_exit_code',
        'invocation_log_sha256','cleanup_process_count','remaining_run_process_count',
        'process_cleanup_observed')
    for ($index = 0; $index -lt 12; $index++) {
        $descriptor = $descriptors[$index]
        $case = $cases[$index]
        $definition = $Current.definitions[$index]
        $expectedPath = "raw/$($definition.case_id).json"
        if (-not (Test-ExactProperties $descriptor $descriptorNames) -or
                -not (Test-JsonInteger $descriptor.ordinal) -or [int]$descriptor.ordinal -ne ($index + 1) -or
                [string]$descriptor.case_id -cne [string]$definition.case_id -or
                [string]$descriptor.path -cne $expectedPath -or
                [string]$descriptor.sha256 -cne [string]$case.raw_report_sha256 -or
                [long]$descriptor.size_bytes -ne [long]$case.raw_report_size -or
                [int]$descriptor.raw_schema -ne 4 -or
                [string]$descriptor.minecraft_version -cne [string]$definition.minecraft_version -or
                [string]$descriptor.backend -cne [string]$definition.backend -or
                [string]$descriptor.proxy -cne [string]$definition.proxy -or
                [string]$descriptor.execution_mode -cne 'EXECUTE' -or
                [int]$descriptor.invocation_exit_code -ne 0 -or
                [string]$descriptor.invocation_log_sha256 -cne [string]$case.invocation_log_sha256 -or
                [int]$descriptor.cleanup_process_count -ne [int]$case.cleanup_process_count -or
                [int]$descriptor.remaining_run_process_count -ne 0 -or
                -not (Test-JsonBoolean $descriptor.process_cleanup_observed) -or
                -not [bool]$descriptor.process_cleanup_observed -or
                [string]$case.raw_report -cne $expectedPath) {
            throw "SERVER_VERSION_MATRIX_RAW_DESCRIPTOR_INVALID|$($definition.case_id)"
        }
        $rawEvidence = Read-StableJson (Join-Path $EvidenceDirectory ($expectedPath.Replace('/','\')))
        Assert-SanitizedEvidenceBytes $rawEvidence.bytes "raw-$($definition.case_id)"
        if ([string]$rawEvidence.digest.sha256 -cne [string]$descriptor.sha256 -or
                [long]$rawEvidence.digest.size -ne [long]$descriptor.size_bytes) {
            throw "SERVER_VERSION_MATRIX_RAW_DESCRIPTOR_BYTES_MISMATCH|$($definition.case_id)"
        }
        Assert-PackagedRawReport $rawEvidence.value $case $definition
    }
    $ordered = Get-OrderedRawReportSetSha256 $descriptors
    if ([string]$manifest.ordered_raw_report_set_sha256 -cne $ordered -or
            [string]$Report.ordered_raw_report_set_sha256 -cne $ordered -or
            [string]$Report.raw_manifest_sha256 -cne [string]$ManifestEvidence.digest.sha256 -or
            [long]$Report.raw_manifest_bytes -ne [long]$ManifestEvidence.digest.size) {
        throw 'SERVER_VERSION_MATRIX_RAW_SET_BINDING_INVALID'
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
    $result = Assert-RawCaseReport $Definition $Current $reportPath $started $finished `
        -InvocationLogSha256 ([string]$log.sha256)
    return [pscustomobject]@{ case=$result; invocation_log_sha256=$log.sha256 }
}

function Assert-CaseBinding {
    param(
        [Parameter(Mandatory)][object]$Case,
        [Parameter(Mandatory)][object]$Definition,
        [Parameter(Mandatory)][object]$Current,
        [string]$EvidenceDirectory
    )
    $names = @(
        'case_id','raw_schema','minecraft_version','minecraft_protocol','server_java_feature','backend','proxy',
        'lane','selector','invocation_started_at','invocation_finished_at','execution_mode',
        'invocation_exit_code','invocation_log_sha256','raw_report',
        'raw_report_sha256','raw_report_size','raw_report_last_write_at','server_asset_identity',
        'proxy_asset_identity','run_root','cleanup_process_count','remaining_run_process_count',
        'sensitive_artifact_count','process_cleanup_observed','passed')
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
            [string]$Case.execution_mode -cne 'EXECUTE' -or
            -not (Test-JsonInteger $Case.invocation_exit_code) -or
            [int]$Case.invocation_exit_code -ne 0 -or
            [string]$Case.invocation_log_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-JsonBoolean $Case.passed) -or -not $Case.passed -or
            [int]$Case.cleanup_process_count -lt 2 -or
            [int]$Case.remaining_run_process_count -ne 0 -or
            [int]$Case.sensitive_artifact_count -ne 0 -or
            -not (Test-JsonBoolean $Case.process_cleanup_observed) -or
            -not [bool]$Case.process_cleanup_observed) {
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
    if (-not [string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
        $expectedPackagedPath = "raw/$($Definition.case_id).json"
        if ([string]$Case.raw_report -cne $expectedPackagedPath) {
            throw "SERVER_VERSION_MATRIX_PACKAGED_RAW_PATH_INVALID|$($Definition.case_id)"
        }
        return
    }
    $rawPath = Resolve-RepositoryRelative ([string]$Case.raw_report) 'raw-report-binding'
    $null = Assert-PathBelow $rawRunsRoot $rawPath 'raw-report-binding'
    $actual = Assert-RawCaseReport $Definition $Current $rawPath $started $finished `
        -InvocationLogSha256 ([string]$Case.invocation_log_sha256) -ReportOnlyValidation
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
        [Parameter(Mandatory)][object]$Current,
        [string]$EvidenceDirectory
    )
    $names = @(
        'schema','generated_at','source_mode','source_commit','release_source_commit',
        'artifact_source_commit','product_version',
        'target_versions','expected_case_count',
        'observed_case_count','stable_case_count','beta_case_count','all_cases_passed',
        'cleanup_all_zero','raw_manifest_schema','raw_manifest_sha256','raw_manifest_bytes',
        'ordered_raw_report_set_sha256','case_runtime_commitment_sha256',
        'release_bundle_manifest_sha256','release_bundle_artifact_set_sha256',
        'matrix_product_jar_set_sha256','supervisor_operation_attempt_id',
        'supervisor_challenge_nonce','supervisor_challenge_issued_at',
        'supervisor_receipt_expires_at','supervisor_trust_root_sha256',
        'supervisor_signer_key_id','supervisor_signature_algorithm',
        'independent_supervisor_signature_present',
        'release_eligible','cases')
    if (-not (Test-ExactProperties $Report $names) -or
            [string]$Report.schema -cne $reportSchema -or
            [string]$Report.source_mode -cne 'EXECUTED' -or
            [string]$Report.source_commit -cne $ExpectedSourceCommit -or
            [string]$Report.artifact_source_commit -cne $ExpectedSourceCommit -or
            [string]$Report.release_source_commit -cnotmatch '^[0-9a-f]{40}$' -or
            [string]$Report.product_version -cne $ProductVersion -or
            ((@($Report.target_versions) -join ',') -cne ($targetVersions -join ',')) -or
            [int]$Report.expected_case_count -ne 12 -or [int]$Report.observed_case_count -ne 12 -or
            [int]$Report.stable_case_count -ne 10 -or [int]$Report.beta_case_count -ne 2 -or
            -not (Test-JsonBoolean $Report.all_cases_passed) -or -not $Report.all_cases_passed -or
            -not (Test-JsonBoolean $Report.cleanup_all_zero) -or -not $Report.cleanup_all_zero -or
            [string]$Report.raw_manifest_schema -cne $rawManifestSchema -or
            [string]$Report.raw_manifest_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-JsonInteger $Report.raw_manifest_bytes) -or [long]$Report.raw_manifest_bytes -le 0 -or
            [string]$Report.ordered_raw_report_set_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Report.case_runtime_commitment_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Report.release_bundle_manifest_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Report.release_bundle_artifact_set_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Report.matrix_product_jar_set_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Report.supervisor_operation_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$Report.supervisor_challenge_nonce -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Report.supervisor_trust_root_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Report.supervisor_signer_key_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$' -or
            [string]$Report.supervisor_signature_algorithm -cne 'RSA_PKCS1_SHA256' -or
            -not (Test-JsonBoolean $Report.independent_supervisor_signature_present) -or
            -not [bool]$Report.independent_supervisor_signature_present -or
            -not (Test-JsonBoolean $Report.release_eligible) -or -not [bool]$Report.release_eligible -or
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
        Assert-CaseBinding $case $definition $Current -EvidenceDirectory $EvidenceDirectory
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
        [Parameter(Mandatory)][long]$ReportBytes,
        [Parameter(Mandatory)][object]$Report,
        [Parameter(Mandatory)][object]$Current
    )
    $names = @(
        'schema','generated_at','report_schema','report_generated_at','report_sha256',
        'report_bytes','source_mode','source_commit','release_source_commit',
        'artifact_source_commit','product_version',
        'raw_manifest_schema','raw_manifest_sha256','raw_manifest_bytes',
        'ordered_raw_report_set_sha256','case_runtime_commitment_sha256',
        'release_bundle_manifest_sha256','release_bundle_artifact_set_sha256',
        'matrix_product_jar_set_sha256','supervisor_operation_attempt_id',
        'supervisor_challenge_nonce','supervisor_challenge_issued_at',
        'supervisor_receipt_expires_at','supervisor_trust_root_sha256',
        'supervisor_signer_key_id','supervisor_signature_algorithm','current_sha256','current',
        'independent_supervisor_signature_present','release_eligible','passed')
    $expectedCurrentBytes = ConvertTo-CompactJsonBytes $Current.public
    $expectedCurrentSha256 = Get-BytesSha256 $expectedCurrentBytes
    if (-not (Test-ExactProperties $Binding $names) -or
            [string]$Binding.schema -cne $bindingSchema -or
            [string]$Binding.generated_at -cne [string]$Report.generated_at -or
            [string]$Binding.report_schema -cne $reportSchema -or
            [string]$Binding.report_generated_at -cne [string]$Report.generated_at -or
            [string]$Binding.report_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Binding.report_sha256 -cne $ReportSha256 -or
            -not (Test-JsonInteger $Binding.report_bytes) -or
            [long]$Binding.report_bytes -ne $ReportBytes -or
            [string]$Binding.source_mode -cne 'EXECUTED' -or
            [string]$Binding.source_commit -cne $ExpectedSourceCommit -or
            [string]$Binding.source_commit -cne [string]$Report.source_commit -or
            [string]$Binding.release_source_commit -cne [string]$Report.release_source_commit -or
            [string]$Binding.artifact_source_commit -cne $ExpectedSourceCommit -or
            [string]$Binding.product_version -cne $ProductVersion -or
            [string]$Binding.product_version -cne [string]$Report.product_version -or
            [string]$Binding.raw_manifest_schema -cne $rawManifestSchema -or
            [string]$Binding.raw_manifest_sha256 -cne [string]$Report.raw_manifest_sha256 -or
            [long]$Binding.raw_manifest_bytes -ne [long]$Report.raw_manifest_bytes -or
            [string]$Binding.ordered_raw_report_set_sha256 -cne [string]$Report.ordered_raw_report_set_sha256 -or
            [string]$Binding.case_runtime_commitment_sha256 -cne [string]$Report.case_runtime_commitment_sha256 -or
            [string]$Binding.release_bundle_manifest_sha256 -cne [string]$Report.release_bundle_manifest_sha256 -or
            [string]$Binding.release_bundle_artifact_set_sha256 -cne [string]$Report.release_bundle_artifact_set_sha256 -or
            [string]$Binding.matrix_product_jar_set_sha256 -cne [string]$Report.matrix_product_jar_set_sha256 -or
            [string]$Binding.supervisor_operation_attempt_id -cne [string]$Report.supervisor_operation_attempt_id -or
            [string]$Binding.supervisor_challenge_nonce -cne [string]$Report.supervisor_challenge_nonce -or
            [string]$Binding.supervisor_challenge_issued_at -cne [string]$Report.supervisor_challenge_issued_at -or
            [string]$Binding.supervisor_receipt_expires_at -cne [string]$Report.supervisor_receipt_expires_at -or
            [string]$Binding.supervisor_trust_root_sha256 -cne [string]$Report.supervisor_trust_root_sha256 -or
            [string]$Binding.supervisor_signer_key_id -cne [string]$Report.supervisor_signer_key_id -or
            [string]$Binding.supervisor_signature_algorithm -cne 'RSA_PKCS1_SHA256' -or
            [string]$Binding.current_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Binding.current_sha256 -cne $expectedCurrentSha256 -or
            -not (Test-JsonBoolean $Binding.independent_supervisor_signature_present) -or
            -not [bool]$Binding.independent_supervisor_signature_present -or
            -not (Test-JsonBoolean $Binding.release_eligible) -or -not [bool]$Binding.release_eligible -or
            -not (Test-JsonBoolean $Binding.passed) -or -not $Binding.passed) {
        throw 'SERVER_VERSION_MATRIX_BINDING_INVALID'
    }
    Compare-PublicBinding $Current.public $Binding.current
}

function Assert-Commit {
    param(
        [Parameter(Mandatory)][object]$Commit,
        [Parameter(Mandatory)][string]$ReportSha256,
        [Parameter(Mandatory)][long]$ReportBytes,
        [Parameter(Mandatory)][string]$BindingSha256,
        [Parameter(Mandatory)][long]$BindingBytes,
        [Parameter(Mandatory)][object]$Report
    )
    $names = @(
        'schema','generated_at','report_schema','binding_schema','report_sha256',
        'report_bytes','binding_sha256','binding_bytes','raw_manifest_schema',
        'raw_manifest_sha256','raw_manifest_bytes','ordered_raw_report_set_sha256',
        'source_commit','release_source_commit','artifact_source_commit','product_version',
        'supervisor_signing_request_schema','supervisor_signing_request_sha256',
        'supervisor_signing_request_bytes','supervisor_receipt_schema',
        'supervisor_receipt_sha256','supervisor_receipt_bytes',
        'supervisor_operation_attempt_id','supervisor_challenge_nonce',
        'supervisor_trust_root_sha256','independent_supervisor_signature_present',
        'release_eligible','committed')
    if (-not (Test-ExactProperties $Commit $names) -or
            [string]$Commit.schema -cne $commitSchema -or
            [string]$Commit.generated_at -cne [string]$Report.generated_at -or
            [string]$Commit.report_schema -cne $reportSchema -or
            [string]$Commit.binding_schema -cne $bindingSchema -or
            [string]$Commit.report_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Commit.report_sha256 -cne $ReportSha256 -or
            -not (Test-JsonInteger $Commit.report_bytes) -or
            [long]$Commit.report_bytes -ne $ReportBytes -or
            [string]$Commit.binding_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Commit.binding_sha256 -cne $BindingSha256 -or
            -not (Test-JsonInteger $Commit.binding_bytes) -or
            [long]$Commit.binding_bytes -ne $BindingBytes -or
            [string]$Commit.raw_manifest_schema -cne $rawManifestSchema -or
            [string]$Commit.raw_manifest_sha256 -cne [string]$Report.raw_manifest_sha256 -or
            [long]$Commit.raw_manifest_bytes -ne [long]$Report.raw_manifest_bytes -or
            [string]$Commit.ordered_raw_report_set_sha256 -cne [string]$Report.ordered_raw_report_set_sha256 -or
            [string]$Commit.source_commit -cne $ExpectedSourceCommit -or
            [string]$Commit.source_commit -cne [string]$Report.source_commit -or
            [string]$Commit.release_source_commit -cne [string]$Report.release_source_commit -or
            [string]$Commit.artifact_source_commit -cne $ExpectedSourceCommit -or
            [string]$Commit.product_version -cne $ProductVersion -or
            [string]$Commit.product_version -cne [string]$Report.product_version -or
            [string]$Commit.supervisor_signing_request_schema -cne $signingRequestSchema -or
            [string]$Commit.supervisor_signing_request_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-JsonInteger $Commit.supervisor_signing_request_bytes) -or
            [long]$Commit.supervisor_signing_request_bytes -le 0 -or
            [string]$Commit.supervisor_receipt_schema -cne $receiptSchema -or
            [string]$Commit.supervisor_receipt_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-JsonInteger $Commit.supervisor_receipt_bytes) -or
            [long]$Commit.supervisor_receipt_bytes -le 0 -or
            [string]$Commit.supervisor_operation_attempt_id -cne [string]$Report.supervisor_operation_attempt_id -or
            [string]$Commit.supervisor_challenge_nonce -cne [string]$Report.supervisor_challenge_nonce -or
            [string]$Commit.supervisor_trust_root_sha256 -cne [string]$Report.supervisor_trust_root_sha256 -or
            -not (Test-JsonBoolean $Commit.independent_supervisor_signature_present) -or
            -not [bool]$Commit.independent_supervisor_signature_present -or
            -not (Test-JsonBoolean $Commit.release_eligible) -or -not [bool]$Commit.release_eligible -or
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
    if ($entries.Count -ne 7) { throw 'SERVER_VERSION_MATRIX_EVIDENCE_PACKAGE_REQUIRED' }
    $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entryName in @('report.json','binding.json','commit.json','raw-manifest.json',
            'supervisor-signing-request.json','supervisor-receipt.json','raw')) {
        [void]$expected.Add($entryName)
    }
    foreach ($entry in $entries) {
        $isRawName = [string]$entry.Name -ceq 'raw'
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($isRawName -and -not $entry.PSIsContainer) -or
                (-not $isRawName -and $entry.PSIsContainer) -or
                -not $expected.Remove([string]$entry.Name)) {
            throw "SERVER_VERSION_MATRIX_EVIDENCE_ENTRY_INVALID|$($entry.Name)"
        }
    }
    if ($expected.Count -ne 0) { throw 'SERVER_VERSION_MATRIX_EVIDENCE_TRIPLET_INCOMPLETE' }
    return $root
}

function Assert-SupervisorEvidencePackage {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][object]$ReportEvidence,
        [Parameter(Mandatory)][object]$BindingEvidence,
        [Parameter(Mandatory)][object]$CommitEvidence,
        [Parameter(Mandatory)][object]$RawManifestEvidence,
        [Parameter(Mandatory)][object]$Current
    )
    $report=$ReportEvidence.value; $binding=$BindingEvidence.value; $commit=$CommitEvidence.value
    $bundle=Read-ReleaseBundleSnapshot
    $productCommitment=Get-MatrixProductCommitment $Current $bundle
    $trustRoot=Read-MatrixSupervisorTrustRoot
    $caseCommitments=[Collections.Generic.List[object]]::new();$processIdentityCount=0
    for($caseIndex=0;$caseIndex -lt 12;$caseIndex++){
        $case=@($report.cases)[$caseIndex]
        $rawPath=Join-Path $Directory (([string]$case.raw_report).Replace('/','\'))
        $raw=(Read-StableJson $rawPath).value
        $processes=[Collections.Generic.List[object]]::new();$cleanupIds=@($raw.cleanup_process_ids)
        for($processIndex=0;$processIndex -lt $cleanupIds.Count;$processIndex++){
            $role=if($processIndex -eq 0){'PROXY'}elseif($processIndex -eq 1){'BACKEND'}else{"AUXILIARY_$($processIndex-1)"}
            $identityBody=[pscustomobject][ordered]@{
                case_id=[string]$case.case_id;role=$role;process_id=[long]$cleanupIds[$processIndex]
                invocation_started_at=[string]$case.invocation_started_at
                invocation_finished_at=[string]$case.invocation_finished_at
                proxy_jar_sha256=[string]$case.run_root.proxy_jar_sha256
                backend_jar_sha256=[string]$case.run_root.backend_jar_sha256
            }
            [void]$processes.Add([pscustomobject][ordered]@{
                role=$role;process_id=[long]$cleanupIds[$processIndex]
                process_incarnation_sha256=Get-SetSha256 'MCACE_SERVER_VERSION_PROCESS_MATRIX_PROCESS_INCARNATION_V1' $identityBody
                cleanup_observed=$true;remaining_process_count=0
            });$processIdentityCount++
        }
        [void]$caseCommitments.Add([pscustomobject][ordered]@{
            ordinal=$caseIndex+1;case_id=[string]$case.case_id
            invocation_started_at=[string]$case.invocation_started_at
            invocation_finished_at=[string]$case.invocation_finished_at
            invocation_log_sha256=[string]$case.invocation_log_sha256
            raw_report_sha256=[string]$case.raw_report_sha256
            raw_report_size_bytes=[long]$case.raw_report_size
            cleanup_process_count=[int]$case.cleanup_process_count
            remaining_process_count=0;process_cleanup_observed=$true;processes=$processes.ToArray()
        })
    }
    $caseValues=$caseCommitments.ToArray();$caseSha=Get-SetSha256 $caseRuntimeDomain $caseValues
    $releaseSha=Get-SetSha256 $releaseArtifactDomain $bundle.artifacts
    if([string]$report.release_source_commit -cne [string]$bundle.release_source_commit -or
            [string]$report.artifact_source_commit -cne [string]$bundle.artifact_source_commit -or
            [string]$report.release_bundle_manifest_sha256 -cne [string]$bundle.manifest_sha256 -or
            [string]$report.release_bundle_artifact_set_sha256 -cne $releaseSha -or
            [string]$report.matrix_product_jar_set_sha256 -cne [string]$productCommitment.sha256 -or
            [string]$report.case_runtime_commitment_sha256 -cne $caseSha -or
            [string]$report.supervisor_trust_root_sha256 -cne [string]$trustRoot.evidence.digest.sha256 -or
            [string]$report.supervisor_signer_key_id -cne [string]$trustRoot.value.key_id){
        throw 'SERVER_VERSION_MATRIX_EXTERNAL_BINDING_INVALID'
    }
    $requestEvidence=Read-StableJson (Join-Path $Directory 'supervisor-signing-request.json')
    $receiptEvidence=Read-StableJson (Join-Path $Directory 'supervisor-receipt.json')
    $request=$requestEvidence.value;$receipt=$receiptEvidence.value
    if([string]$request.schema -cne $signingRequestSchema -or
            [string]$request.source_mode -cne 'EXECUTED_AWAITING_EXTERNAL_SUPERVISOR' -or
            [string]$request.release_source_commit -cne [string]$bundle.release_source_commit -or
            [string]$request.artifact_source_commit -cne $ExpectedSourceCommit -or
            [string]$request.operation_attempt_id -cne [string]$report.supervisor_operation_attempt_id -or
            [string]$request.challenge_nonce -cne [string]$report.supervisor_challenge_nonce -or
            [string]$request.challenge_issued_at -cne [string]$report.supervisor_challenge_issued_at -or
            [string]$request.receipt_not_after -cne [string]$report.supervisor_receipt_expires_at -or
            [string]$request.report_sha256 -cne [string]$ReportEvidence.digest.sha256 -or
            [long]$request.report_size_bytes -ne [long]$ReportEvidence.digest.size -or
            [string]$request.binding_sha256 -cne [string]$BindingEvidence.digest.sha256 -or
            [long]$request.binding_size_bytes -ne [long]$BindingEvidence.digest.size -or
            [string]$request.raw_manifest_sha256 -cne [string]$RawManifestEvidence.digest.sha256 -or
            [long]$request.raw_manifest_size_bytes -ne [long]$RawManifestEvidence.digest.size -or
            [string]$request.case_runtime_commitment_sha256 -cne $caseSha -or
            [int]$request.case_count -ne 12 -or [int]$request.process_identity_count -ne $processIdentityCount -or
            (Get-SetSha256 $caseRuntimeDomain @($request.case_runtime_commitments)) -cne $caseSha -or
            [string]$request.release_bundle_manifest_sha256 -cne [string]$bundle.manifest_sha256 -or
            [string]$request.release_bundle_artifact_set_sha256 -cne $releaseSha -or
            (Get-SetSha256 $releaseArtifactDomain @($request.release_bundle_artifacts)) -cne $releaseSha -or
            [string]$request.matrix_product_jar_set_sha256 -cne [string]$productCommitment.sha256 -or
            (Get-SetSha256 $matrixProductDomain @($request.matrix_product_jars)) -cne [string]$productCommitment.sha256 -or
            [string]$request.supervisor_trust_root_sha256 -cne [string]$trustRoot.evidence.digest.sha256 -or
            [string]$request.supervisor_signer_key_id -cne [string]$trustRoot.value.key_id -or
            [string]$request.signature_algorithm -cne 'RSA_PKCS1_SHA256'){
        throw 'SERVER_VERSION_MATRIX_SUPERVISOR_SIGNING_REQUEST_INVALID'
    }
    if(-not(Test-ExactProperties $receipt $matrixReceiptPropertyNames) -or
            [string]$receipt.schema -cne $receiptSchema -or
            [string]$receipt.artifact_class -cne 'EXTERNALLY_SIGNED_MATRIX_SUPERVISOR_RECEIPT' -or
            [string]$receipt.source_mode -cne 'EXTERNAL_MATRIX_SUPERVISOR' -or
            -not(Test-JsonBoolean $receipt.supervisor_independent) -or -not[bool]$receipt.supervisor_independent -or
            -not(Test-JsonBoolean $receipt.test_fixture) -or [bool]$receipt.test_fixture -or
            [string]$receipt.signer_key_id -cne [string]$trustRoot.value.key_id -or
            [string]$receipt.signer_trust_root_sha256 -cne [string]$trustRoot.evidence.digest.sha256 -or
            [string]$receipt.signature_algorithm -cne 'RSA_PKCS1_SHA256'){
        throw 'SERVER_VERSION_MATRIX_SUPERVISOR_RECEIPT_PROVENANCE_INVALID'
    }
    $map=[ordered]@{
        release_source_commit='release_source_commit';artifact_source_commit='artifact_source_commit'
        product_version='product_version';operation_attempt_id='operation_attempt_id'
        challenge_nonce='challenge_nonce';challenge_issued_at='challenge_issued_at'
        report_sha256='report_sha256';report_size_bytes='report_size_bytes'
        binding_sha256='binding_sha256';binding_size_bytes='binding_size_bytes'
        raw_manifest_sha256='raw_manifest_sha256';raw_manifest_size_bytes='raw_manifest_size_bytes'
        ordered_raw_report_set_sha256='ordered_raw_report_set_sha256'
        case_runtime_commitment_sha256='case_runtime_commitment_sha256';case_count='case_count'
        process_identity_count='process_identity_count';release_bundle_schema='release_bundle_schema'
        release_bundle_manifest_sha256='release_bundle_manifest_sha256'
        release_bundle_manifest_size_bytes='release_bundle_manifest_size_bytes'
        release_bundle_sha256s_sha256='release_bundle_sha256s_sha256'
        release_bundle_sha256s_size_bytes='release_bundle_sha256s_size_bytes'
        release_bundle_artifact_set_sha256='release_bundle_artifact_set_sha256'
        release_bundle_artifact_count='release_bundle_artifact_count'
        matrix_product_jar_set_sha256='matrix_product_jar_set_sha256'
        matrix_product_jar_count='matrix_product_jar_count'
    }
    foreach($pair in $map.GetEnumerator()){
        $actual=$receipt.([string]$pair.Key);$expected=$request.([string]$pair.Value)
        if(Test-JsonInteger $expected){if(-not(Test-JsonInteger $actual)-or[long]$actual-ne[long]$expected){throw 'SERVER_VERSION_MATRIX_SUPERVISOR_RECEIPT_BINDING_INVALID'}}
        elseif([string]$actual -cne [string]$expected){throw 'SERVER_VERSION_MATRIX_SUPERVISOR_RECEIPT_BINDING_INVALID'}
    }
    $issued=ConvertTo-ExactDateTimeOffset $request.challenge_issued_at 'request.challenge_issued_at'
    $expires=ConvertTo-ExactDateTimeOffset $request.receipt_not_after 'request.receipt_not_after'
    $signed=ConvertTo-ExactDateTimeOffset $receipt.signed_at 'receipt.signed_at'
    $receiptExpires=ConvertTo-ExactDateTimeOffset $receipt.expires_at 'receipt.expires_at'
    if($expires.Ticks-ne$receiptExpires.Ticks-or$signed-lt$issued-or$signed-gt$expires-or
            [DateTimeOffset]::UtcNow-gt$expires.AddMinutes(1)){throw 'SERVER_VERSION_MATRIX_SUPERVISOR_RECEIPT_EXPIRED_OR_TIME_INVALID'}
    try{$signature=[Convert]::FromBase64String([string]$receipt.signature_base64)}catch{throw 'SERVER_VERSION_MATRIX_SUPERVISOR_RECEIPT_SIGNATURE_ENCODING_INVALID'}
    if($signature.Length-ne$trustRoot.modulus.Length-or-not(Test-RsaPkcs1Sha256Signature (Get-MatrixReceiptSigningPayload $receipt) $signature $trustRoot.modulus $trustRoot.exponent)){
        throw 'SERVER_VERSION_MATRIX_SUPERVISOR_RECEIPT_SIGNATURE_INVALID'
    }
    if([string]$commit.supervisor_signing_request_sha256-cne[string]$requestEvidence.digest.sha256-or
            [long]$commit.supervisor_signing_request_bytes-ne[long]$requestEvidence.digest.size-or
            [string]$commit.supervisor_receipt_sha256-cne[string]$receiptEvidence.digest.sha256-or
            [long]$commit.supervisor_receipt_bytes-ne[long]$receiptEvidence.digest.size){
        throw 'SERVER_VERSION_MATRIX_COMMIT_SUPERVISOR_DOCUMENT_BINDING_INVALID'
    }
    return @($requestEvidence,$receiptEvidence)
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
    $rawManifestPath = Join-Path $directory 'raw-manifest.json'
    $reportEvidence = Read-StableJson $resolvedReport
    $bindingEvidence = Read-StableJson $bindingPath
    $commitEvidence = Read-StableJson $commitPath
    $rawManifestEvidence = Read-StableJson $rawManifestPath
    Assert-SanitizedEvidenceBytes $reportEvidence.bytes 'report'
    Assert-SanitizedEvidenceBytes $bindingEvidence.bytes 'binding'
    Assert-SanitizedEvidenceBytes $commitEvidence.bytes 'commit'
    Assert-SanitizedEvidenceBytes $rawManifestEvidence.bytes 'raw-manifest'
    Assert-Report $reportEvidence.value $Current -EvidenceDirectory $directory
    Assert-RawManifest $rawManifestEvidence $reportEvidence.value $Current $directory
    Assert-Binding $bindingEvidence.value $reportEvidence.digest.sha256 `
        $reportEvidence.digest.size `
        $reportEvidence.value $Current
    Assert-Commit $commitEvidence.value $reportEvidence.digest.sha256 `
        $reportEvidence.digest.size $bindingEvidence.digest.sha256 `
        $bindingEvidence.digest.size $reportEvidence.value
    $supervisorDocuments = @(Assert-SupervisorEvidencePackage $directory $reportEvidence `
        $bindingEvidence $commitEvidence $rawManifestEvidence $Current)
    foreach ($evidence in @($reportEvidence,$bindingEvidence,$commitEvidence,$rawManifestEvidence) +
            $supervisorDocuments) {
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
    $bundle = Read-ReleaseBundleSnapshot
    $productCommitment = Get-MatrixProductCommitment $Current $bundle
    $trustRoot = Read-MatrixSupervisorTrustRoot
    $exchangeRoot = Assert-OutOfBandDirectory $SupervisorExchangeRoot 'SUPERVISOR_EXCHANGE_ROOT'
    if (Test-FullPathBelow $exchangeRoot ([string]$trustRoot.evidence.digest.path)) {
        throw 'SERVER_VERSION_MATRIX_SELF_SUPERVISOR_TRUST_ROOT_REJECTED'
    }

    $generatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    $challengeIssuedAt = $generatedAt
    $receiptNotAfter = [DateTimeOffset]::UtcNow.AddMinutes(15).ToString('o')
    $operationAttemptId = [Guid]::NewGuid().ToString('N')
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $challengeBytes = New-Object byte[] 32
        $random.GetBytes($challengeBytes)
    } finally { $random.Dispose() }
    $challengeNonce = ConvertTo-LowerHex $challengeBytes

    $rawSources = [Collections.Generic.List[object]]::new()
    $rawDescriptors = [Collections.Generic.List[object]]::new()
    $publishedCases = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt 12; $index++) {
        $case = $Cases[$index]
        $definition = $Current.definitions[$index]
        Assert-CaseBinding $case $definition $Current
        $sourcePath = Resolve-RepositoryRelative ([string]$case.raw_report) 'raw-report-publication'
        $source = Read-StableJson $sourcePath
        if ([string]$source.digest.sha256 -cne [string]$case.raw_report_sha256 -or
                [long]$source.digest.size -ne [long]$case.raw_report_size) {
            throw "SERVER_VERSION_MATRIX_RAW_PUBLICATION_BYTES_MISMATCH|$($case.case_id)"
        }
        Assert-SanitizedEvidenceBytes $source.bytes "raw-publication-$($case.case_id)"
        $publishedPath = "raw/$($case.case_id).json"
        [void]$rawSources.Add([pscustomobject]@{
            path=$publishedPath; bytes=[byte[]]$source.bytes; value=$source.value
        })
        [void]$rawDescriptors.Add([pscustomobject][ordered]@{
            ordinal=$index+1; case_id=[string]$case.case_id; path=$publishedPath
            sha256=[string]$source.digest.sha256; size_bytes=[long]$source.digest.size
            raw_schema=4; minecraft_version=[string]$case.minecraft_version
            backend=[string]$case.backend; proxy=[string]$case.proxy
            execution_mode='EXECUTE'; invocation_exit_code=0
            invocation_log_sha256=[string]$case.invocation_log_sha256
            cleanup_process_count=[int]$case.cleanup_process_count
            remaining_run_process_count=0; process_cleanup_observed=$true
        })
        [void]$publishedCases.Add([pscustomobject][ordered]@{
            case_id=[string]$case.case_id; raw_schema=4
            minecraft_version=[string]$case.minecraft_version
            minecraft_protocol=[int]$case.minecraft_protocol
            server_java_feature=[int]$case.server_java_feature
            backend=[string]$case.backend; proxy=[string]$case.proxy
            lane=[string]$case.lane; selector=[string]$case.selector
            invocation_started_at=[string]$case.invocation_started_at
            invocation_finished_at=[string]$case.invocation_finished_at
            execution_mode='EXECUTE'; invocation_exit_code=0
            invocation_log_sha256=[string]$case.invocation_log_sha256
            raw_report=$publishedPath; raw_report_sha256=[string]$source.digest.sha256
            raw_report_size=[long]$source.digest.size
            raw_report_last_write_at=[string]$case.raw_report_last_write_at
            server_asset_identity=[string]$case.server_asset_identity
            proxy_asset_identity=[string]$case.proxy_asset_identity; run_root=$case.run_root
            cleanup_process_count=[int]$case.cleanup_process_count
            remaining_run_process_count=0; sensitive_artifact_count=0
            process_cleanup_observed=$true; passed=$true
        })
    }

    $caseCommitments = [Collections.Generic.List[object]]::new()
    $processIdentityCount = 0
    for ($caseIndex=0; $caseIndex -lt 12; $caseIndex++) {
        $case=@($publishedCases)[$caseIndex]; $raw=@($rawSources)[$caseIndex].value
        $processes=[Collections.Generic.List[object]]::new()
        $cleanupIds=@($raw.cleanup_process_ids)
        for($processIndex=0;$processIndex -lt $cleanupIds.Count;$processIndex++) {
            $role=if($processIndex -eq 0){'PROXY'}elseif($processIndex -eq 1){'BACKEND'}else{"AUXILIARY_$($processIndex-1)"}
            $identityBody=[pscustomobject][ordered]@{
                case_id=[string]$case.case_id; role=$role; process_id=[long]$cleanupIds[$processIndex]
                invocation_started_at=[string]$case.invocation_started_at
                invocation_finished_at=[string]$case.invocation_finished_at
                proxy_jar_sha256=[string]$case.run_root.proxy_jar_sha256
                backend_jar_sha256=[string]$case.run_root.backend_jar_sha256
            }
            [void]$processes.Add([pscustomobject][ordered]@{
                role=$role; process_id=[long]$cleanupIds[$processIndex]
                process_incarnation_sha256=Get-SetSha256 'MCACE_SERVER_VERSION_PROCESS_MATRIX_PROCESS_INCARNATION_V1' $identityBody
                cleanup_observed=$true; remaining_process_count=0
            })
            $processIdentityCount++
        }
        [void]$caseCommitments.Add([pscustomobject][ordered]@{
            ordinal=$caseIndex+1; case_id=[string]$case.case_id
            invocation_started_at=[string]$case.invocation_started_at
            invocation_finished_at=[string]$case.invocation_finished_at
            invocation_log_sha256=[string]$case.invocation_log_sha256
            raw_report_sha256=[string]$case.raw_report_sha256
            raw_report_size_bytes=[long]$case.raw_report_size
            cleanup_process_count=[int]$case.cleanup_process_count
            remaining_process_count=0; process_cleanup_observed=$true
            processes=$processes.ToArray()
        })
    }
    $caseCommitmentValues=$caseCommitments.ToArray()
    $caseCommitmentSha256=Get-SetSha256 $caseRuntimeDomain $caseCommitmentValues
    $orderedRawSetSha256=Get-OrderedRawReportSetSha256 $rawDescriptors.ToArray()
    $rawManifest=[pscustomobject][ordered]@{
        schema=$rawManifestSchema; generated_at=$generatedAt; source_mode='EXECUTED'
        source_commit=$ExpectedSourceCommit; product_version=$ProductVersion; case_count=12
        ordered_raw_report_set_sha256=$orderedRawSetSha256; reports=$rawDescriptors.ToArray()
    }
    $rawManifestBytes=ConvertTo-CompactJsonBytes $rawManifest
    Assert-SanitizedEvidenceBytes $rawManifestBytes 'new-raw-manifest'
    $rawManifestSha256=Get-BytesSha256 $rawManifestBytes

    $report=[pscustomobject][ordered]@{
        schema=$reportSchema; generated_at=$generatedAt; source_mode='EXECUTED'
        source_commit=$ExpectedSourceCommit; release_source_commit=$bundle.release_source_commit
        artifact_source_commit=$ExpectedSourceCommit; product_version=$ProductVersion
        target_versions=@($targetVersions); expected_case_count=12; observed_case_count=12
        stable_case_count=10; beta_case_count=2; all_cases_passed=$true; cleanup_all_zero=$true
        raw_manifest_schema=$rawManifestSchema; raw_manifest_sha256=$rawManifestSha256
        raw_manifest_bytes=[long]$rawManifestBytes.Length
        ordered_raw_report_set_sha256=$orderedRawSetSha256
        case_runtime_commitment_sha256=$caseCommitmentSha256
        release_bundle_manifest_sha256=$bundle.manifest_sha256
        release_bundle_artifact_set_sha256=$bundle.artifact_set_sha256
        matrix_product_jar_set_sha256=$productCommitment.sha256
        supervisor_operation_attempt_id=$operationAttemptId
        supervisor_challenge_nonce=$challengeNonce
        supervisor_challenge_issued_at=$challengeIssuedAt
        supervisor_receipt_expires_at=$receiptNotAfter
        supervisor_trust_root_sha256=[string]$trustRoot.evidence.digest.sha256
        supervisor_signer_key_id=[string]$trustRoot.value.key_id
        supervisor_signature_algorithm='RSA_PKCS1_SHA256'
        independent_supervisor_signature_present=$true; release_eligible=$true
        cases=$publishedCases.ToArray()
    }
    $reportBytes=ConvertTo-CompactJsonBytes $report
    Assert-SanitizedEvidenceBytes $reportBytes 'new-report'
    $reportSha256=Get-BytesSha256 $reportBytes
    $currentBytes=ConvertTo-CompactJsonBytes $Current.public
    $binding=[pscustomobject][ordered]@{
        schema=$bindingSchema; generated_at=$generatedAt; report_schema=$reportSchema
        report_generated_at=$generatedAt; report_sha256=$reportSha256
        report_bytes=[long]$reportBytes.Length; source_mode='EXECUTED'
        source_commit=$ExpectedSourceCommit; release_source_commit=$bundle.release_source_commit
        artifact_source_commit=$ExpectedSourceCommit; product_version=$ProductVersion
        raw_manifest_schema=$rawManifestSchema; raw_manifest_sha256=$rawManifestSha256
        raw_manifest_bytes=[long]$rawManifestBytes.Length
        ordered_raw_report_set_sha256=$orderedRawSetSha256
        case_runtime_commitment_sha256=$caseCommitmentSha256
        release_bundle_manifest_sha256=$bundle.manifest_sha256
        release_bundle_artifact_set_sha256=$bundle.artifact_set_sha256
        matrix_product_jar_set_sha256=$productCommitment.sha256
        supervisor_operation_attempt_id=$operationAttemptId
        supervisor_challenge_nonce=$challengeNonce
        supervisor_challenge_issued_at=$challengeIssuedAt
        supervisor_receipt_expires_at=$receiptNotAfter
        supervisor_trust_root_sha256=[string]$trustRoot.evidence.digest.sha256
        supervisor_signer_key_id=[string]$trustRoot.value.key_id
        supervisor_signature_algorithm='RSA_PKCS1_SHA256'
        current_sha256=(Get-BytesSha256 $currentBytes); current=$Current.public
        independent_supervisor_signature_present=$true; release_eligible=$true; passed=$true
    }
    $bindingBytes=ConvertTo-CompactJsonBytes $binding
    Assert-SanitizedEvidenceBytes $bindingBytes 'new-binding'
    $bindingSha256=Get-BytesSha256 $bindingBytes

    $signingRequest=[pscustomobject][ordered]@{
        schema=$signingRequestSchema; generated_at=$generatedAt
        source_mode='EXECUTED_AWAITING_EXTERNAL_SUPERVISOR'
        release_source_commit=$bundle.release_source_commit; artifact_source_commit=$ExpectedSourceCommit
        product_version=$ProductVersion; operation_attempt_id=$operationAttemptId
        challenge_nonce=$challengeNonce; challenge_issued_at=$challengeIssuedAt
        receipt_not_after=$receiptNotAfter; report_sha256=$reportSha256
        report_size_bytes=[long]$reportBytes.Length; binding_sha256=$bindingSha256
        binding_size_bytes=[long]$bindingBytes.Length; raw_manifest_sha256=$rawManifestSha256
        raw_manifest_size_bytes=[long]$rawManifestBytes.Length
        ordered_raw_report_set_sha256=$orderedRawSetSha256
        case_runtime_commitment_sha256=$caseCommitmentSha256; case_count=12
        process_identity_count=$processIdentityCount; case_runtime_commitments=$caseCommitmentValues
        release_bundle_schema='MCACE_RELEASE_BUNDLE_V4'
        release_bundle_manifest_sha256=$bundle.manifest_sha256
        release_bundle_manifest_size_bytes=[long]$bundle.manifest_bytes
        release_bundle_sha256s_sha256=$bundle.sha256s_sha256
        release_bundle_sha256s_size_bytes=[long]$bundle.sha256s_bytes
        release_bundle_artifact_set_sha256=$bundle.artifact_set_sha256
        release_bundle_artifact_count=6; release_bundle_artifacts=$bundle.artifacts
        matrix_product_jar_set_sha256=$productCommitment.sha256
        matrix_product_jar_count=3; matrix_product_jars=$productCommitment.values
        supervisor_trust_root_sha256=[string]$trustRoot.evidence.digest.sha256
        supervisor_signer_key_id=[string]$trustRoot.value.key_id
        signature_algorithm='RSA_PKCS1_SHA256'
    }
    $signingRequestBytes=ConvertTo-CompactJsonBytes $signingRequest
    Assert-SanitizedEvidenceBytes $signingRequestBytes 'supervisor-signing-request'
    $signingRequestSha256=Get-BytesSha256 $signingRequestBytes

    $runName=[DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH-mm-ss-fffffffZ')
    $finalRoot=Join-Path $evidenceRunsRoot $runName
    $stagingRoot=Join-Path $evidenceRunsRoot ('.staging-'+$runName+'-'+[IO.Path]::GetRandomFileName())
    if((Test-Path -LiteralPath $finalRoot) -or (Test-Path -LiteralPath $stagingRoot)){
        throw 'SERVER_VERSION_MATRIX_EVIDENCE_RUN_COLLISION'
    }
    [void][IO.Directory]::CreateDirectory($stagingRoot)
    try {
        $rawRoot=Join-Path $stagingRoot 'raw';[void][IO.Directory]::CreateDirectory($rawRoot)
        foreach($rawSource in $rawSources){
            Write-NewFileBytes (Join-Path $stagingRoot (([string]$rawSource.path).Replace('/','\'))) ([byte[]]$rawSource.bytes)
        }
        Write-NewFileBytes (Join-Path $stagingRoot 'raw-manifest.json') $rawManifestBytes
        $stagingReport=Join-Path $stagingRoot 'report.json'
        Write-NewFileBytes $stagingReport $reportBytes
        Write-NewFileBytes (Join-Path $stagingRoot 'binding.json') $bindingBytes
        Write-NewFileBytes (Join-Path $stagingRoot 'supervisor-signing-request.json') $signingRequestBytes

        $externalRequest=Join-Path $exchangeRoot ("request-$operationAttemptId.json")
        $externalReceipt=Join-Path $exchangeRoot ("receipt-$operationAttemptId.json")
        if((Test-Path -LiteralPath $externalRequest) -or (Test-Path -LiteralPath $externalReceipt)){
            throw 'SERVER_VERSION_MATRIX_SUPERVISOR_EXCHANGE_REPLAY_OR_COLLISION'
        }
        Write-NewFileBytes $externalRequest $signingRequestBytes
        Write-Host "SERVER_VERSION_MATRIX_SIGNING_REQUEST_READY|request=$externalRequest|receipt=$externalReceipt|attempt=$operationAttemptId|challenge=$challengeNonce"
        $deadline=[DateTimeOffset]::UtcNow.AddSeconds($SupervisorReceiptWaitSeconds)
        while(-not(Test-Path -LiteralPath $externalReceipt -PathType Leaf)){
            if([DateTimeOffset]::UtcNow -ge $deadline){throw 'SERVER_VERSION_MATRIX_SUPERVISOR_RECEIPT_TIMEOUT'}
            Start-Sleep -Milliseconds 250
        }
        $receiptEvidence=Read-StableJson $externalReceipt
        $receipt=$receiptEvidence.value
        if(-not(Test-ExactProperties $receipt $matrixReceiptPropertyNames)){
            throw 'SERVER_VERSION_MATRIX_SUPERVISOR_RECEIPT_SCHEMA_INVALID'
        }
        $expected=[ordered]@{
            release_source_commit=$bundle.release_source_commit; artifact_source_commit=$ExpectedSourceCommit
            product_version=$ProductVersion; operation_attempt_id=$operationAttemptId
            challenge_nonce=$challengeNonce; challenge_issued_at=$challengeIssuedAt
            report_sha256=$reportSha256; report_size_bytes=[long]$reportBytes.Length
            binding_sha256=$bindingSha256; binding_size_bytes=[long]$bindingBytes.Length
            raw_manifest_sha256=$rawManifestSha256; raw_manifest_size_bytes=[long]$rawManifestBytes.Length
            ordered_raw_report_set_sha256=$orderedRawSetSha256
            case_runtime_commitment_sha256=$caseCommitmentSha256; case_count=12
            process_identity_count=$processIdentityCount; release_bundle_schema='MCACE_RELEASE_BUNDLE_V4'
            release_bundle_manifest_sha256=$bundle.manifest_sha256
            release_bundle_manifest_size_bytes=[long]$bundle.manifest_bytes
            release_bundle_sha256s_sha256=$bundle.sha256s_sha256
            release_bundle_sha256s_size_bytes=[long]$bundle.sha256s_bytes
            release_bundle_artifact_set_sha256=$bundle.artifact_set_sha256
            release_bundle_artifact_count=6; matrix_product_jar_set_sha256=$productCommitment.sha256
            matrix_product_jar_count=3
        }
        if([string]$receipt.schema -cne $receiptSchema -or
                [string]$receipt.artifact_class -cne 'EXTERNALLY_SIGNED_MATRIX_SUPERVISOR_RECEIPT' -or
                [string]$receipt.source_mode -cne 'EXTERNAL_MATRIX_SUPERVISOR' -or
                -not(Test-JsonBoolean $receipt.supervisor_independent) -or -not[bool]$receipt.supervisor_independent -or
                -not(Test-JsonBoolean $receipt.test_fixture) -or [bool]$receipt.test_fixture -or
                [string]$receipt.signer_key_id -cne [string]$trustRoot.value.key_id -or
                [string]$receipt.signer_trust_root_sha256 -cne [string]$trustRoot.evidence.digest.sha256 -or
                [string]$receipt.signature_algorithm -cne 'RSA_PKCS1_SHA256'){
            throw 'SERVER_VERSION_MATRIX_SUPERVISOR_RECEIPT_PROVENANCE_INVALID'
        }
        foreach($pair in $expected.GetEnumerator()){
            $actual=$receipt.([string]$pair.Key)
            if(Test-JsonInteger $pair.Value){
                if(-not(Test-JsonInteger $actual) -or [long]$actual -ne [long]$pair.Value){throw "SERVER_VERSION_MATRIX_SUPERVISOR_RECEIPT_BINDING_INVALID|$($pair.Key)"}
            }elseif([string]$actual -cne [string]$pair.Value){throw "SERVER_VERSION_MATRIX_SUPERVISOR_RECEIPT_BINDING_INVALID|$($pair.Key)"}
        }
        $signedAt=ConvertTo-ExactDateTimeOffset $receipt.signed_at 'receipt.signed_at'
        $expiresAt=ConvertTo-ExactDateTimeOffset $receipt.expires_at 'receipt.expires_at'
        $issuedAt=ConvertTo-ExactDateTimeOffset $challengeIssuedAt 'challenge_issued_at'
        if($expiresAt.Ticks -ne (ConvertTo-ExactDateTimeOffset $receiptNotAfter 'receipt_not_after').Ticks -or
                $signedAt -lt $issuedAt -or $signedAt -gt $expiresAt -or [DateTimeOffset]::UtcNow -gt $expiresAt){
            throw 'SERVER_VERSION_MATRIX_SUPERVISOR_RECEIPT_EXPIRED_OR_TIME_INVALID'
        }
        try{$signature=[Convert]::FromBase64String([string]$receipt.signature_base64)}
        catch{throw 'SERVER_VERSION_MATRIX_SUPERVISOR_RECEIPT_SIGNATURE_ENCODING_INVALID'}
        if($signature.Length -ne $trustRoot.modulus.Length -or
                -not(Test-RsaPkcs1Sha256Signature (Get-MatrixReceiptSigningPayload $receipt) $signature $trustRoot.modulus $trustRoot.exponent)){
            throw 'SERVER_VERSION_MATRIX_SUPERVISOR_RECEIPT_SIGNATURE_INVALID'
        }
        if((Get-BytesSha256 (ConvertTo-CompactJsonBytes $receipt)) -cne [string]$receiptEvidence.digest.sha256){
            throw 'SERVER_VERSION_MATRIX_SUPERVISOR_RECEIPT_NONCANONICAL'
        }
        $bundleAfter=Read-ReleaseBundleSnapshot
        if($bundleAfter.manifest_sha256 -cne $bundle.manifest_sha256 -or
                $bundleAfter.sha256s_sha256 -cne $bundle.sha256s_sha256 -or
                $bundleAfter.artifact_set_sha256 -cne $bundle.artifact_set_sha256){
            throw 'SERVER_VERSION_MATRIX_RELEASE_BUNDLE_CHANGED_DURING_SUPERVISION'
        }
        $rootAfter=Get-StableFileDigest ([string]$trustRoot.evidence.digest.path)
        if($rootAfter.sha256 -cne [string]$trustRoot.evidence.digest.sha256 -or
                $rootAfter.size -ne [long]$trustRoot.evidence.digest.size){
            throw 'SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_CHANGED'
        }
        Write-NewFileBytes (Join-Path $stagingRoot 'supervisor-receipt.json') ([byte[]]$receiptEvidence.bytes)
        $commit=[pscustomobject][ordered]@{
            schema=$commitSchema; generated_at=$generatedAt; report_schema=$reportSchema
            binding_schema=$bindingSchema; report_sha256=$reportSha256
            report_bytes=[long]$reportBytes.Length; binding_sha256=$bindingSha256
            binding_bytes=[long]$bindingBytes.Length; raw_manifest_schema=$rawManifestSchema
            raw_manifest_sha256=$rawManifestSha256; raw_manifest_bytes=[long]$rawManifestBytes.Length
            ordered_raw_report_set_sha256=$orderedRawSetSha256; source_commit=$ExpectedSourceCommit
            release_source_commit=$bundle.release_source_commit; artifact_source_commit=$ExpectedSourceCommit
            product_version=$ProductVersion; supervisor_signing_request_schema=$signingRequestSchema
            supervisor_signing_request_sha256=$signingRequestSha256
            supervisor_signing_request_bytes=[long]$signingRequestBytes.Length
            supervisor_receipt_schema=$receiptSchema
            supervisor_receipt_sha256=[string]$receiptEvidence.digest.sha256
            supervisor_receipt_bytes=[long]$receiptEvidence.digest.size
            supervisor_operation_attempt_id=$operationAttemptId
            supervisor_challenge_nonce=$challengeNonce
            supervisor_trust_root_sha256=[string]$trustRoot.evidence.digest.sha256
            independent_supervisor_signature_present=$true; release_eligible=$true; committed=$true
        }
        $commitBytes=ConvertTo-CompactJsonBytes $commit
        Assert-SanitizedEvidenceBytes $commitBytes 'new-commit'
        # The commit marker is deliberately the last staged write.
        Write-NewFileBytes (Join-Path $stagingRoot 'commit.json') $commitBytes
        $null=Assert-EvidenceTriplet $stagingReport $Current -AllowStaging
        [IO.Directory]::Move($stagingRoot,$finalRoot)
        $finalReport=Join-Path $finalRoot 'report.json'
        $null=Assert-EvidenceTriplet $finalReport $Current
        return $finalReport
    } finally {
        if(Test-Path -LiteralPath $stagingRoot -PathType Container){
            [IO.Directory]::Delete((Assert-DirectLocalPath $stagingRoot -Directory),$true)
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
Assert-ExactGitSourceIdentity

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
