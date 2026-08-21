[CmdletBinding(DefaultParameterSetName = 'ReportOnly')]
param(
    [Parameter(ParameterSetName = 'Execute', Mandatory = $true)]
    [switch]$Execute,

    [Parameter(ParameterSetName = 'ReportOnly')]
    [switch]$ReportOnly,

    [Parameter(ParameterSetName = 'RegisterPrepared', Mandatory = $true)]
    [switch]$RegisterPrepared,

    [Parameter(ParameterSetName = 'ReportOnly', DontShow = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$MetadataFixtureDirectory = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This preparer has three deliberately separate modes:
#   * the default/ReportOnly mode performs no network request and no write;
#   * Execute resolves the six PaperMC builds, downloads only immutable reviewed
#     artifacts, verifies SHA-256 and size, and writes one path-free manifest.
#   * RegisterPrepared performs no network request. It binds only the existing
#     cache/libraries/versions trees to canonical relative names, sizes and hashes.

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$assetRoot = Join-Path $repoRoot 'build\runtime-assets'
$manifestFile = Join-Path $assetRoot 'manifest.json'
$preparedManifestFile = Join-Path $assetRoot 'prepared-manifest.json'
$userAgent = 'MCAce-server-version-matrix-preparer/1 (https://github.com/EllanServer/MCAce)'
$targetVersions = @('1.21.11', '26.1.2', '26.2')
$projects = @('paper', 'folia')
$reportMode = $PSCmdlet.ParameterSetName -eq 'ReportOnly'
$executeMode = $PSCmdlet.ParameterSetName -eq 'Execute'
$registerPreparedMode = $PSCmdlet.ParameterSetName -eq 'RegisterPrepared'
$preparedRoots = @('cache', 'libraries', 'versions')

$javaByVersion = [ordered]@{
    '1.21.11' = 21
    '26.1.2' = 25
    '26.2' = 25
}

$reviewedProxyAssets = @(
    [ordered]@{
        project = 'velocity'
        version = '3.5.1-615'
        build = '615'
        url = 'https://fill-data.papermc.io/v1/objects/b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3/velocity-3.5.1-615.jar'
        sha256 = 'b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3'
        size = 18932366
        channel = 'REVIEWED'
        java_major = 21
        target_versions = @('1.21.11', '26.1.2', '26.2')
    },
    [ordered]@{
        project = 'bungeecord'
        version = '2085'
        build = '2085'
        url = 'https://hub.spigotmc.org/jenkins/job/BungeeCord/2085/artifact/bootstrap/target/BungeeCord.jar'
        sha256 = 'e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce'
        size = 25599274
        channel = 'REVIEWED'
        java_major = 21
        target_versions = @('1.21.11', '26.1.2', '26.2')
    }
)

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-ObjectProperty([object]$Value, [string]$Name) {
    if ($null -eq $Value) { return $null }
    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function ConvertFrom-JsonContent([object]$Content) {
    if ($Content -is [byte[]]) {
        $Content = [Text.Encoding]::UTF8.GetString([byte[]]$Content)
    }
    return ([string]$Content) | ConvertFrom-Json -ErrorAction Stop
}

function Get-OfficialBuilds([string]$Project, [string]$MinecraftVersion) {
    $uri = "https://fill.papermc.io/v3/projects/$Project/versions/$MinecraftVersion/builds"
    if (-not [string]::IsNullOrWhiteSpace($MetadataFixtureDirectory)) {
        $fixtureName = "$Project-$MinecraftVersion.json"
        $fixturePath = Join-Path $MetadataFixtureDirectory $fixtureName
        if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
            throw "SERVER_MATRIX_FIXTURE_MISSING|$fixtureName"
        }
        return [pscustomobject]@{
            uri = $uri
            builds = ConvertFrom-JsonContent (Get-Content -LiteralPath $fixturePath -Raw)
            source = 'FIXTURE'
        }
    }
    if ($reportMode) {
        return [pscustomobject]@{
            uri = $uri
            builds = $null
            source = 'UNRESOLVED_OFFLINE'
        }
    }
    $response = Invoke-WebRequest -UseBasicParsing -Headers @{ 'User-Agent' = $userAgent } `
        -Uri $uri -TimeoutSec 60
    return [pscustomobject]@{
        uri = $uri
        builds = ConvertFrom-JsonContent $response.Content
        source = 'OFFICIAL_FILL_API'
    }
}

function ConvertTo-BuildArray([object]$Response) {
    if ($null -eq $Response) { return @() }
    $nested = Get-ObjectProperty $Response 'builds'
    if ($null -ne $nested) { return @($nested) }
    return @($Response)
}

function Test-AllowedChannel([string]$Project, [string]$MinecraftVersion, [string]$Channel) {
    $normalized = $Channel.ToUpperInvariant()
    if ($normalized -in @('STABLE', 'RECOMMENDED')) { return $true }
    # Folia 26.2 is currently an explicit experimental lane. It is prepared and
    # labelled, never promoted into the stable lane by this tool.
    return $Project -eq 'folia' -and $MinecraftVersion -eq '26.2' -and
        $normalized -in @('EXPERIMENTAL', 'ALPHA', 'BETA')
}

function Assert-PaperMcDownload(
        [string]$Project,
        [string]$MinecraftVersion,
        [object]$Build) {
    $id = Get-ObjectProperty $Build 'id'
    $channel = [string](Get-ObjectProperty $Build 'channel')
    if ($null -eq $id -or [string]::IsNullOrWhiteSpace($channel)) {
        throw "SERVER_MATRIX_BUILD_IDENTITY_INVALID|$Project|$MinecraftVersion"
    }
    $downloads = Get-ObjectProperty $Build 'downloads'
    $download = Get-ObjectProperty $downloads 'server:default'
    if ($null -eq $download) {
        throw "SERVER_MATRIX_DEFAULT_DOWNLOAD_MISSING|$Project|$MinecraftVersion|$id"
    }
    $url = [string](Get-ObjectProperty $download 'url')
    $checksums = Get-ObjectProperty $download 'checksums'
    $sha256 = [string](Get-ObjectProperty $checksums 'sha256')
    $sizeValue = Get-ObjectProperty $download 'size'
    if ([string]::IsNullOrWhiteSpace($url) -or $sha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw "SERVER_MATRIX_DOWNLOAD_IDENTITY_INVALID|$Project|$MinecraftVersion|$id"
    }
    $sha256 = $sha256.ToLowerInvariant()
    $urlMatch = [regex]::Match(
        $url,
        '^https://fill-data\.papermc\.io/v1/objects/(?<sha>[0-9a-f]{64})/[^/?#]+$')
    if (-not $urlMatch.Success -or $urlMatch.Groups['sha'].Value -ne $sha256) {
        throw "SERVER_MATRIX_DOWNLOAD_ORIGIN_INVALID|$Project|$MinecraftVersion|$id"
    }
    $size = 0L
    if ($null -ne $sizeValue) {
        try { $size = [Convert]::ToInt64($sizeValue) }
        catch { throw "SERVER_MATRIX_DOWNLOAD_SIZE_INVALID|$Project|$MinecraftVersion|$id" }
    }
    if ($size -le 0L) {
        throw "SERVER_MATRIX_DOWNLOAD_SIZE_INVALID|$Project|$MinecraftVersion|$id"
    }
    return [ordered]@{
        project = $Project
        version = $MinecraftVersion
        build = [string]$id
        url = $url
        sha256 = $sha256
        size = $size
        channel = $channel.ToUpperInvariant()
        java_major = [int]$javaByVersion[$MinecraftVersion]
    }
}

function Select-OfficialBuild(
        [string]$Project,
        [string]$MinecraftVersion,
        [object]$Response) {
    $usable = @()
    foreach ($build in @(ConvertTo-BuildArray $Response)) {
        $channelValue = Get-ObjectProperty $build 'channel'
        if ($null -eq $channelValue) { continue }
        if (Test-AllowedChannel $Project $MinecraftVersion ([string]$channelValue)) {
            $usable += $build
        }
    }
    $selected = $usable | Sort-Object -Property @{ Expression = {
        $id = Get-ObjectProperty $_ 'id'
        try { return [Convert]::ToInt64($id) } catch { return [Int64]::MinValue }
    }; Descending = $true } | Select-Object -First 1
    if ($null -eq $selected) {
        throw "SERVER_MATRIX_NO_ALLOWED_BUILD|$Project|$MinecraftVersion"
    }
    return Assert-PaperMcDownload $Project $MinecraftVersion $selected
}

function Assert-ReviewedProxyAsset([object]$Asset) {
    $sha256 = [string]$Asset.sha256
    if ($sha256 -notmatch '^[0-9a-f]{64}$' -or [long]$Asset.size -le 0L) {
        throw "SERVER_MATRIX_REVIEWED_PROXY_INVALID|$($Asset.project)"
    }
    if ($Asset.project -eq 'velocity') {
        $match = [regex]::Match(
            [string]$Asset.url,
            '^https://fill-data\.papermc\.io/v1/objects/(?<sha>[0-9a-f]{64})/velocity-3\.5\.1-615\.jar$')
        if (-not $match.Success -or $match.Groups['sha'].Value -ne $sha256 -or
                $sha256 -cne 'b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3' -or
                [long]$Asset.size -ne 18932366L -or $Asset.version -cne '3.5.1-615' -or
                $Asset.build -cne '615') {
            throw 'SERVER_MATRIX_REVIEWED_PROXY_INVALID|velocity'
        }
    } elseif ($Asset.project -eq 'bungeecord') {
        if ($Asset.url -cne 'https://hub.spigotmc.org/jenkins/job/BungeeCord/2085/artifact/bootstrap/target/BungeeCord.jar' -or
                $sha256 -cne 'e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce' -or
                [long]$Asset.size -ne 25599274L -or $Asset.version -cne '2085' -or
                $Asset.build -cne '2085') {
            throw 'SERVER_MATRIX_REVIEWED_PROXY_INVALID|bungeecord'
        }
    } else {
        throw "SERVER_MATRIX_REVIEWED_PROXY_INVALID|$($Asset.project)"
    }
}

function Get-AssetFile([object]$Asset) {
    if ($Asset.project -in @('paper', 'folia')) {
        return Join-Path $assetRoot (Join-Path $Asset.project `
            (Join-Path $Asset.version (Join-Path $Asset.build 'server.jar')))
    }
    if ($Asset.project -eq 'velocity') {
        return Join-Path $assetRoot (Join-Path 'velocity' (Join-Path $Asset.version 'server.jar'))
    }
    if ($Asset.project -eq 'bungeecord') {
        return Join-Path $assetRoot (Join-Path 'bungeecord' (Join-Path $Asset.build 'server.jar'))
    }
    throw "SERVER_MATRIX_UNKNOWN_PROJECT|$($Asset.project)"
}

function Get-CacheStatus([object]$Asset) {
    $path = Get-AssetFile $Asset
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return 'MISSING' }
    $item = Get-Item -LiteralPath $path
    if ($item.Length -ne [long]$Asset.size) { return 'SIZE_MISMATCH' }
    if ((Get-Sha256 $path) -cne [string]$Asset.sha256) { return 'SHA256_MISMATCH' }
    return 'VERIFIED'
}

function Install-VerifiedAsset([object]$Asset) {
    $status = Get-CacheStatus $Asset
    if ($status -eq 'VERIFIED') { return }
    if ($status -ne 'MISSING') {
        throw "SERVER_MATRIX_EXISTING_CACHE_INVALID|$($Asset.project)|$($Asset.version)|$status"
    }
    $path = Get-AssetFile $Asset
    $directory = Split-Path -Parent $path
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $temporary = Join-Path $directory ('server.jar.download-' + [Guid]::NewGuid().ToString('N'))
    try {
        Invoke-WebRequest -UseBasicParsing -Headers @{ 'User-Agent' = $userAgent } `
            -Uri $Asset.url -OutFile $temporary -TimeoutSec 300
        $item = Get-Item -LiteralPath $temporary
        if ($item.Length -ne [long]$Asset.size) {
            throw "SERVER_MATRIX_DOWNLOADED_SIZE_MISMATCH|$($Asset.project)|$($Asset.version)"
        }
        if ((Get-Sha256 $temporary) -cne [string]$Asset.sha256) {
            throw "SERVER_MATRIX_DOWNLOADED_SHA256_MISMATCH|$($Asset.project)|$($Asset.version)"
        }
        Move-Item -LiteralPath $temporary -Destination $path
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Test-ExactAssetFields([object]$Asset) {
    $expected = @('build', 'channel', 'java_major', 'project', 'sha256', 'size', 'url', 'version')
    if ($Asset.project -in @('velocity', 'bungeecord')) { $expected += 'target_versions' }
    $actual = @($Asset.PSObject.Properties | ForEach-Object Name | Sort-Object)
    $wanted = @($expected | Sort-Object)
    return $actual.Count -eq $wanted.Count -and (($actual -join "`n") -ceq ($wanted -join "`n"))
}

function Assert-PathFreeManifest([object]$Manifest) {
    if ($Manifest.schema -cne 'MCACE_SERVER_VERSION_MATRIX_ASSETS_V1' -or
            $Manifest.prepared_tree_status -cne 'DEFERRED' -or @($Manifest.assets).Count -ne 8) {
        throw 'SERVER_MATRIX_MANIFEST_SCHEMA_INVALID'
    }
    $identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($asset in @($Manifest.assets)) {
        if (-not (Test-ExactAssetFields $asset) -or
                $asset.sha256 -notmatch '^[0-9a-f]{64}$' -or [long]$asset.size -le 0L -or
                [int]$asset.java_major -notin @(21, 25) -or
                [string]::IsNullOrWhiteSpace([string]$asset.url) -or
                [string]::IsNullOrWhiteSpace([string]$asset.channel)) {
            throw 'SERVER_MATRIX_MANIFEST_ASSET_INVALID'
        }
        if ($asset.project -in @('paper', 'folia')) {
            if ($asset.version -notin $targetVersions -or $asset.build -notmatch '^[0-9]+$' -or
                    [int]$asset.java_major -ne [int]$javaByVersion[$asset.version] -or
                    -not (Test-AllowedChannel $asset.project $asset.version $asset.channel)) {
                throw 'SERVER_MATRIX_MANIFEST_ASSET_INVALID'
            }
            $urlMatch = [regex]::Match(
                [string]$asset.url,
                '^https://fill-data\.papermc\.io/v1/objects/(?<sha>[0-9a-f]{64})/[^/?#]+$')
            if (-not $urlMatch.Success -or $urlMatch.Groups['sha'].Value -cne $asset.sha256) {
                throw 'SERVER_MATRIX_MANIFEST_ASSET_INVALID'
            }
            $identity = "$($asset.project):$($asset.version)"
        } elseif ($asset.project -in @('velocity', 'bungeecord')) {
            Assert-ReviewedProxyAsset $asset
            if (@($asset.target_versions) -join ',' -cne '1.21.11,26.1.2,26.2') {
                throw 'SERVER_MATRIX_MANIFEST_ASSET_INVALID'
            }
            $identity = "$($asset.project):$($asset.version)"
        } else {
            throw 'SERVER_MATRIX_MANIFEST_ASSET_INVALID'
        }
        if (-not $identities.Add($identity)) { throw 'SERVER_MATRIX_MANIFEST_DUPLICATE_ASSET' }
    }
    $expectedIdentities = @(
        'paper:1.21.11', 'paper:26.1.2', 'paper:26.2',
        'folia:1.21.11', 'folia:26.1.2', 'folia:26.2',
        'velocity:3.5.1-615', 'bungeecord:2085')
    foreach ($identity in $expectedIdentities) {
        if (-not $identities.Contains($identity)) { throw 'SERVER_MATRIX_MANIFEST_ASSET_SET_INVALID' }
    }
    $json = $Manifest | ConvertTo-Json -Depth 12 -Compress
    if ($json -match '(?i)"[^"\r\n]*(?:path|directory|root)[^"\r\n]*"\s*:' -or
            $json.IndexOf($repoRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            (-not [string]::IsNullOrWhiteSpace($MetadataFixtureDirectory) -and
                $json.IndexOf($MetadataFixtureDirectory, [StringComparison]::OrdinalIgnoreCase) -ge 0)) {
        throw 'SERVER_MATRIX_MANIFEST_PATH_DISCLOSURE'
    }
}

function Read-FrozenManifest {
    if (-not (Test-Path -LiteralPath $manifestFile -PathType Leaf)) { return $null }
    $manifestItem = Get-Item -LiteralPath $manifestFile -Force
    if (($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'SERVER_MATRIX_MANIFEST_REPARSE_POINT'
    }
    $manifest = ConvertFrom-JsonContent (Get-Content -LiteralPath $manifestFile -Raw)
    Assert-PathFreeManifest $manifest
    return $manifest
}

function Write-FrozenManifest([object]$Manifest) {
    Assert-PathFreeManifest $Manifest
    New-Item -ItemType Directory -Force -Path $assetRoot | Out-Null
    $temporary = Join-Path $assetRoot ('manifest.json.tmp-' + [Guid]::NewGuid().ToString('N'))
    try {
        [IO.File]::WriteAllText(
            $temporary,
            ($Manifest | ConvertTo-Json -Depth 12),
            [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $manifestFile -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Test-ExactPropertyNames([object]$Value, [string[]]$Expected) {
    if ($null -eq $Value) { return $false }
    $actual = @($Value.PSObject.Properties | ForEach-Object Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    return $actual.Count -eq $wanted.Count -and (($actual -join "`n") -ceq ($wanted -join "`n"))
}

function Get-PreparedDirectory([object]$Asset) {
    if ($Asset.project -notin @('paper', 'folia')) {
        throw "SERVER_MATRIX_PREPARED_UNKNOWN_PROJECT|$($Asset.project)"
    }
    return Join-Path $assetRoot (Join-Path $Asset.project `
        (Join-Path $Asset.version (Join-Path $Asset.build 'prepared')))
}

function Assert-RealDirectory([string]$Path, [string]$Identity) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "SERVER_MATRIX_PREPARED_DIRECTORY_MISSING|$Identity"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer) {
        throw "SERVER_MATRIX_PREPARED_DIRECTORY_MISSING|$Identity"
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "SERVER_MATRIX_PREPARED_REPARSE_POINT|$Identity"
    }
    return [IO.Path]::GetFullPath($item.FullName)
}

function Assert-CanonicalPreparedRelative([string]$Relative) {
    if ([string]::IsNullOrWhiteSpace($Relative) -or $Relative -cne $Relative.Normalize() -or
            $Relative.IndexOf('\') -ge 0 -or $Relative.StartsWith('/') -or
            $Relative -match '^[A-Za-z]:' -or $Relative -match '(^|/)\.{1,2}($|/)' -or
            $Relative.IndexOf('//') -ge 0) {
        throw "SERVER_MATRIX_PREPARED_RELATIVE_INVALID|$Relative"
    }
    $parts = @($Relative.Split('/'))
    if ($parts.Count -lt 2 -or $parts[0] -notin $preparedRoots -or
            @($parts | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -ne 0) {
        throw "SERVER_MATRIX_PREPARED_RELATIVE_INVALID|$Relative"
    }
}

function Get-PreparedTreeSnapshot([object]$Asset) {
    $identity = "$($Asset.project):$($Asset.version):$($Asset.build)"
    $preparedDirectory = Get-PreparedDirectory $Asset
    $current = Assert-RealDirectory $assetRoot 'runtime-assets'
    foreach ($segment in @([string]$Asset.project, [string]$Asset.version, [string]$Asset.build, 'prepared')) {
        $current = Join-Path $current $segment
        $current = Assert-RealDirectory $current "$identity|$segment"
    }
    $preparedFull = [IO.Path]::GetFullPath($current)
    if ($preparedFull -cne [IO.Path]::GetFullPath($preparedDirectory)) {
        throw "SERVER_MATRIX_PREPARED_ESCAPE|$identity"
    }
    $preparedPrefix = $preparedFull.TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
    $comparison = if ([IO.Path]::DirectorySeparatorChar -eq '\') {
        [StringComparison]::OrdinalIgnoreCase
    } else {
        [StringComparison]::Ordinal
    }
    $records = [Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::Ordinal)
    $canonicalKeys = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($root in $preparedRoots) {
        $rootPath = Join-Path $preparedFull $root
        [void](Assert-RealDirectory $rootPath "${identity}:$root")
        foreach ($item in @(Get-ChildItem -LiteralPath $rootPath -Recurse -Force)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "SERVER_MATRIX_PREPARED_REPARSE_POINT|$identity|$($item.Name)"
            }
            if ($item.PSIsContainer) { continue }
            if (-not ($item -is [IO.FileInfo])) {
                throw "SERVER_MATRIX_PREPARED_UNKNOWN_ENTRY|$identity|$($item.Name)"
            }
            $full = [IO.Path]::GetFullPath($item.FullName)
            if (-not $full.StartsWith($preparedPrefix, $comparison)) {
                throw "SERVER_MATRIX_PREPARED_ESCAPE|$identity|$($item.Name)"
            }
            $relative = $full.Substring($preparedPrefix.Length).Replace('\', '/').Normalize()
            Assert-CanonicalPreparedRelative $relative
            if (-not $canonicalKeys.Add($relative)) {
                throw "SERVER_MATRIX_PREPARED_DUPLICATE_RELATIVE|$identity|$relative"
            }
            $records.Add($relative, [pscustomobject][ordered]@{
                relative = $relative
                size = [long]$item.Length
                sha256 = Get-Sha256 $full
            })
        }
    }
    if ($records.Count -eq 0) { throw "SERVER_MATRIX_PREPARED_EMPTY|$identity" }
    $files = [Collections.Generic.List[object]]::new()
    foreach ($pair in $records.GetEnumerator()) { [void]$files.Add($pair.Value) }
    return [pscustomobject][ordered]@{
        project = [string]$Asset.project
        version = [string]$Asset.version
        build = [string]$Asset.build
        server_sha256 = [string]$Asset.sha256
        files = @($files)
    }
}

function Get-ServerAssetMap([object]$AssetManifest) {
    $result = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($asset in @($AssetManifest.assets | Where-Object { $_.project -in @('paper', 'folia') })) {
        $identity = "$($asset.project):$($asset.version):$($asset.build)"
        if ($result.ContainsKey($identity)) { throw 'SERVER_MATRIX_PREPARED_DUPLICATE_SOURCE_ASSET' }
        $result.Add($identity, $asset)
    }
    if ($result.Count -ne 6) { throw 'SERVER_MATRIX_PREPARED_SOURCE_ASSET_SET_INVALID' }
    return $result
}

function Assert-PreparedManifestStructure([object]$Manifest, [object]$AssetManifest) {
    if (-not (Test-ExactPropertyNames $Manifest @('schema', 'generated_at', 'roots', 'trees')) -or
            $Manifest.schema -cne 'MCACE_SERVER_VERSION_MATRIX_PREPARED_V1' -or
            [string]::IsNullOrWhiteSpace([string]$Manifest.generated_at) -or
            ((@($Manifest.roots) -join ',') -cne 'cache,libraries,versions') -or
            @($Manifest.trees).Count -ne 6) {
        throw 'SERVER_MATRIX_PREPARED_MANIFEST_SCHEMA_INVALID'
    }
    $sourceAssets = Get-ServerAssetMap $AssetManifest
    $treeIdentities = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($tree in @($Manifest.trees)) {
        if (-not (Test-ExactPropertyNames $tree @('project', 'version', 'build', 'server_sha256', 'files')) -or
                $tree.project -notin @('paper', 'folia') -or $tree.server_sha256 -notmatch '^[0-9a-f]{64}$' -or
                @($tree.files).Count -eq 0) {
            throw 'SERVER_MATRIX_PREPARED_MANIFEST_TREE_INVALID'
        }
        $identity = "$($tree.project):$($tree.version):$($tree.build)"
        if (-not $treeIdentities.Add($identity) -or -not $sourceAssets.ContainsKey($identity)) {
            throw "SERVER_MATRIX_PREPARED_MANIFEST_UNKNOWN_TREE|$identity"
        }
        $sourceAsset = $sourceAssets[$identity]
        if ($tree.server_sha256 -cne [string]$sourceAsset.sha256) {
            throw "SERVER_MATRIX_PREPARED_MANIFEST_SOURCE_MISMATCH|$identity"
        }
        $relatives = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($file in @($tree.files)) {
            if (-not (Test-ExactPropertyNames $file @('relative', 'size', 'sha256')) -or
                    $file.sha256 -notmatch '^[0-9a-f]{64}$') {
                throw "SERVER_MATRIX_PREPARED_MANIFEST_FILE_INVALID|$identity"
            }
            $size = -1L
            try { $size = [Convert]::ToInt64($file.size) } catch { $size = -1L }
            if ($size -lt 0L) { throw "SERVER_MATRIX_PREPARED_MANIFEST_FILE_INVALID|$identity" }
            $relative = [string]$file.relative
            Assert-CanonicalPreparedRelative $relative
            if (-not $relatives.Add($relative)) {
                throw "SERVER_MATRIX_PREPARED_MANIFEST_DUPLICATE_RELATIVE|$identity|$relative"
            }
        }
    }
    foreach ($identity in $sourceAssets.Keys) {
        if (-not $treeIdentities.Contains($identity)) {
            throw "SERVER_MATRIX_PREPARED_MANIFEST_MISSING_TREE|$identity"
        }
    }
    $json = $Manifest | ConvertTo-Json -Depth 20 -Compress
    if ($json.IndexOf($repoRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $json.IndexOf($assetRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $json -match '(?i)"[^"\r\n]*(?:absolute|directory|root_path|repo_path)[^"\r\n]*"\s*:') {
        throw 'SERVER_MATRIX_PREPARED_MANIFEST_PATH_DISCLOSURE'
    }
}

function Compare-PreparedManifest([object]$Manifest, [object]$AssetManifest) {
    Assert-PreparedManifestStructure $Manifest $AssetManifest
    $manifestTrees = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($tree in @($Manifest.trees)) {
        $manifestTrees.Add("$($tree.project):$($tree.version):$($tree.build)", $tree)
    }
    $verified = [Collections.Generic.List[object]]::new()
    foreach ($sourceAsset in @($AssetManifest.assets | Where-Object { $_.project -in @('paper', 'folia') })) {
        $identity = "$($sourceAsset.project):$($sourceAsset.version):$($sourceAsset.build)"
        $expectedTree = $manifestTrees[$identity]
        $actualTree = Get-PreparedTreeSnapshot $sourceAsset
        $expectedFiles = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
        foreach ($file in @($expectedTree.files)) { $expectedFiles.Add([string]$file.relative, $file) }
        if ($expectedFiles.Count -ne @($actualTree.files).Count) {
            throw "SERVER_MATRIX_PREPARED_TREE_CONTENT_MISMATCH|$identity|COUNT"
        }
        $totalSize = 0L
        foreach ($file in @($actualTree.files)) {
            if (-not $expectedFiles.ContainsKey($file.relative)) {
                throw "SERVER_MATRIX_PREPARED_TREE_UNKNOWN_FILE|$identity|$($file.relative)"
            }
            $expected = $expectedFiles[$file.relative]
            if ([long]$expected.size -ne [long]$file.size -or
                    [string]$expected.sha256 -cne [string]$file.sha256) {
                throw "SERVER_MATRIX_PREPARED_TREE_CONTENT_MISMATCH|$identity|$($file.relative)"
            }
            $totalSize += [long]$file.size
        }
        [void]$verified.Add([pscustomobject][ordered]@{
            project = [string]$sourceAsset.project
            version = [string]$sourceAsset.version
            build = [string]$sourceAsset.build
            status = 'VERIFIED'
            file_count = @($actualTree.files).Count
            total_size = $totalSize
        })
    }
    return [pscustomobject]@{
        status = 'VERIFIED'
        verified_count = $verified.Count
        expected_count = 6
        trees = @($verified)
    }
}

function New-PreparedManifest([object]$AssetManifest) {
    $trees = [Collections.Generic.List[object]]::new()
    [void](Get-ServerAssetMap $AssetManifest)
    foreach ($sourceAsset in @($AssetManifest.assets | Where-Object { $_.project -in @('paper', 'folia') })) {
        $cacheStatus = Get-CacheStatus $sourceAsset
        if ($cacheStatus -cne 'VERIFIED') {
            throw "SERVER_MATRIX_PREPARED_SOURCE_CACHE_INVALID|$($sourceAsset.project)|$($sourceAsset.version)|$cacheStatus"
        }
        [void]$trees.Add((Get-PreparedTreeSnapshot $sourceAsset))
    }
    $manifest = [pscustomobject][ordered]@{
        schema = 'MCACE_SERVER_VERSION_MATRIX_PREPARED_V1'
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        roots = @($preparedRoots)
        trees = @($trees)
    }
    Assert-PreparedManifestStructure $manifest $AssetManifest
    return $manifest
}

function Write-PreparedManifest([object]$Manifest) {
    New-Item -ItemType Directory -Force -Path $assetRoot | Out-Null
    $temporary = Join-Path $assetRoot ('prepared-manifest.json.tmp-' + [Guid]::NewGuid().ToString('N'))
    try {
        [IO.File]::WriteAllText(
            $temporary,
            ($Manifest | ConvertTo-Json -Depth 20),
            [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $preparedManifestFile -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Read-PreparedManifest([object]$AssetManifest, [bool]$Required) {
    if (-not (Test-Path -LiteralPath $preparedManifestFile -PathType Leaf)) {
        if ($Required) { throw 'SERVER_MATRIX_PREPARED_MANIFEST_MISSING' }
        return $null
    }
    $manifestItem = Get-Item -LiteralPath $preparedManifestFile -Force
    if (($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'SERVER_MATRIX_PREPARED_MANIFEST_REPARSE_POINT'
    }
    $manifest = ConvertFrom-JsonContent (Get-Content -LiteralPath $preparedManifestFile -Raw)
    Assert-PreparedManifestStructure $manifest $AssetManifest
    return $manifest
}

function ConvertTo-ReportAsset([object]$Asset, [string]$ResolutionSource) {
    $result = [ordered]@{
        project = $Asset.project
        version = $Asset.version
        build = $Asset.build
        url = $Asset.url
        sha256 = $Asset.sha256
        size = [long]$Asset.size
        channel = $Asset.channel
        java_major = [int]$Asset.java_major
    }
    if ($Asset.project -in @('velocity', 'bungeecord')) {
        $result.target_versions = @($Asset.target_versions)
    }
    $result.resolution_source = $ResolutionSource
    $result.cache_status = Get-CacheStatus $Asset
    return $result
}

function New-UnresolvedReportAsset([string]$Project, [string]$MinecraftVersion) {
    return [ordered]@{
        project = $Project
        version = $MinecraftVersion
        build = $null
        metadata_url = "https://fill.papermc.io/v3/projects/$Project/versions/$MinecraftVersion/builds"
        java_major = [int]$javaByVersion[$MinecraftVersion]
        resolution_source = 'UNRESOLVED_OFFLINE'
        cache_status = 'UNKNOWN_UNTIL_RESOLVED'
    }
}

$resolvedAssets = [System.Collections.Generic.List[object]]::new()
$reportAssets = [System.Collections.Generic.List[object]]::new()
$frozenManifest = $null

if ($registerPreparedMode) {
    $frozenManifest = Read-FrozenManifest
    if ($null -eq $frozenManifest) { throw 'SERVER_MATRIX_FROZEN_MANIFEST_MISSING' }
    $preparedManifest = New-PreparedManifest $frozenManifest
    Write-PreparedManifest $preparedManifest
    $preparedManifest = Read-PreparedManifest $frozenManifest $true
    $preparedSummary = Compare-PreparedManifest $preparedManifest $frozenManifest
    foreach ($asset in @($frozenManifest.assets)) {
        [void]$resolvedAssets.Add($asset)
        [void]$reportAssets.Add((ConvertTo-ReportAsset $asset 'FROZEN_MANIFEST'))
    }
    $registerReport = [ordered]@{
        schema = 'MCACE_SERVER_VERSION_MATRIX_PREPARER_REPORT_V1'
        mode = 'REGISTER_PREPARED'
        network_requested = $false
        write_requested = $true
        manifest_written = $false
        prepared_manifest_present = $true
        prepared_manifest_written = $true
        prepared_tree_status = $preparedSummary.status
        prepared_verified_count = $preparedSummary.verified_count
        prepared_expected_count = $preparedSummary.expected_count
        all_prepared_trees_verified = $preparedSummary.verified_count -eq $preparedSummary.expected_count
        prepared_trees = @($preparedSummary.trees)
        target_versions = @($targetVersions)
        resolved_asset_count = $resolvedAssets.Count
        expected_asset_count = 8
        all_assets_resolved = $resolvedAssets.Count -eq 8
        all_resolved_assets_cached = $resolvedAssets.Count -eq 8 -and
            @($reportAssets | Where-Object { $_.cache_status -ne 'VERIFIED' }).Count -eq 0
        assets = @($reportAssets)
    }
    Write-Output ($registerReport | ConvertTo-Json -Depth 20 -Compress)
    return
}

if ($executeMode) {
    # Windows PowerShell 5.1 may otherwise negotiate an obsolete protocol before
    # it reaches the official HTTPS endpoints. This mutation is execute-only.
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

if ($reportMode -and [string]::IsNullOrWhiteSpace($MetadataFixtureDirectory)) {
    $frozenManifest = Read-FrozenManifest
}

if ($null -ne $frozenManifest) {
    foreach ($asset in @($frozenManifest.assets)) {
        [void]$resolvedAssets.Add($asset)
        [void]$reportAssets.Add((ConvertTo-ReportAsset $asset 'FROZEN_MANIFEST'))
    }
} else {
    foreach ($project in $projects) {
        foreach ($minecraftVersion in $targetVersions) {
            $metadata = Get-OfficialBuilds $project $minecraftVersion
            if ($null -eq $metadata.builds) {
                [void]$reportAssets.Add((New-UnresolvedReportAsset $project $minecraftVersion))
                continue
            }
            $asset = Select-OfficialBuild $project $minecraftVersion $metadata.builds
            [void]$resolvedAssets.Add([pscustomobject]$asset)
            [void]$reportAssets.Add((ConvertTo-ReportAsset ([pscustomobject]$asset) $metadata.source))
        }
    }
    foreach ($proxyAsset in $reviewedProxyAssets) {
        $asset = [pscustomobject]$proxyAsset
        Assert-ReviewedProxyAsset $asset
        [void]$resolvedAssets.Add($asset)
        [void]$reportAssets.Add((ConvertTo-ReportAsset $asset 'REVIEWED_PIN'))
    }
}

$manifestWritten = $false
if ($executeMode) {
    if ($resolvedAssets.Count -ne 8) { throw 'SERVER_MATRIX_EXECUTE_REQUIRES_EIGHT_RESOLVED_ASSETS' }
    foreach ($asset in $resolvedAssets) { Install-VerifiedAsset $asset }
    $manifest = [ordered]@{
        schema = 'MCACE_SERVER_VERSION_MATRIX_ASSETS_V1'
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        prepared_tree_status = 'DEFERRED'
        assets = @($resolvedAssets)
    }
    Assert-PathFreeManifest ([pscustomobject]$manifest)
    Write-FrozenManifest ([pscustomobject]$manifest)
    $manifestWritten = $true
    $reportAssets.Clear()
    foreach ($asset in $resolvedAssets) {
        [void]$reportAssets.Add((ConvertTo-ReportAsset $asset 'EXECUTED_AND_FROZEN'))
    }
}

$preparedManifestPresent = Test-Path -LiteralPath $preparedManifestFile -PathType Leaf
$preparedStatus = 'DEFERRED'
$preparedVerifiedCount = 0
$preparedExpectedCount = 6
$preparedTrees = @()
if ($reportMode -and [string]::IsNullOrWhiteSpace($MetadataFixtureDirectory) -and
        $preparedManifestPresent) {
    if ($null -eq $frozenManifest) { throw 'SERVER_MATRIX_PREPARED_SOURCE_MANIFEST_MISSING' }
    $preparedManifest = Read-PreparedManifest $frozenManifest $true
    $preparedSummary = Compare-PreparedManifest $preparedManifest $frozenManifest
    $preparedStatus = $preparedSummary.status
    $preparedVerifiedCount = $preparedSummary.verified_count
    $preparedExpectedCount = $preparedSummary.expected_count
    $preparedTrees = @($preparedSummary.trees)
} elseif ($reportMode -and -not [string]::IsNullOrWhiteSpace($MetadataFixtureDirectory)) {
    $preparedStatus = 'NOT_EVALUATED_FIXTURE'
}

$report = [ordered]@{
    schema = 'MCACE_SERVER_VERSION_MATRIX_PREPARER_REPORT_V1'
    mode = if ($reportMode) { 'REPORT_ONLY' } else { 'EXECUTE' }
    network_requested = $executeMode
    write_requested = $executeMode
    manifest_written = $manifestWritten
    prepared_manifest_present = [bool]$preparedManifestPresent
    prepared_manifest_written = $false
    prepared_tree_status = $preparedStatus
    prepared_verified_count = $preparedVerifiedCount
    prepared_expected_count = $preparedExpectedCount
    all_prepared_trees_verified = $preparedVerifiedCount -eq $preparedExpectedCount
    prepared_trees = @($preparedTrees)
    target_versions = @($targetVersions)
    resolved_asset_count = $resolvedAssets.Count
    expected_asset_count = 8
    all_assets_resolved = $resolvedAssets.Count -eq 8
    all_resolved_assets_cached = $resolvedAssets.Count -eq 8 -and
        @($reportAssets | Where-Object { $_.cache_status -ne 'VERIFIED' }).Count -eq 0
    assets = @($reportAssets)
}

Write-Output ($report | ConvertTo-Json -Depth 20 -Compress)
