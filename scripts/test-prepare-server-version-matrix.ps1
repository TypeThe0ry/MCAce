[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$target = Join-Path $PSScriptRoot 'prepare-server-version-matrix.ps1'
$tokens = $null
$parseErrors = $null
[Management.Automation.Language.Parser]::ParseFile($target, [ref]$tokens, [ref]$parseErrors) | Out-Null
if (@($parseErrors).Count -ne 0) {
    throw "SERVER_MATRIX_PREPARER_PARSE_FAILED|$($parseErrors -join '; ')"
}

$source = Get-Content -LiteralPath $target -Raw
$staticChecks = [ordered]@{
    default_report_only = $source -match "DefaultParameterSetName\s*=\s*'ReportOnly'"
    explicit_execute = $source -match "ParameterSetName\s*=\s*'Execute'" -and
        $source -match '\[switch\]\$Execute'
    explicit_register_prepared = $source -match "ParameterSetName\s*=\s*'RegisterPrepared'" -and
        $source -match '\[switch\]\$RegisterPrepared'
    six_papermc_targets = $source -match "@\('1\.21\.11', '26\.1\.2', '26\.2'\)" -and
        $source -match "@\('paper', 'folia'\)"
    exact_cache_layout = $source -match "'build\\runtime-assets'" -and
        $source -match 'Join-Path \$Asset\.build ''server\.jar'''
    immutable_fill_origin = $source -match 'fill-data\\\.papermc\\\.io/v1/objects'
    immutable_sha_and_size = $source -match 'DOWNLOADED_SHA256_MISMATCH' -and
        $source -match 'DOWNLOADED_SIZE_MISMATCH'
    prepared_deferred = $source -match "prepared_tree_status = 'DEFERRED'"
    prepared_manifest = $source -match "'prepared-manifest\.json'" -and
        $source -match 'MCACE_SERVER_VERSION_MATRIX_PREPARED_V1'
    prepared_roots_only = $source -match "@\('cache', 'libraries', 'versions'\)"
    prepared_reparse_guard = $source -match 'PREPARED_REPARSE_POINT'
    prepared_canonical_relative = $source -match 'Assert-CanonicalPreparedRelative' -and
        $source -match '\.Replace\('
    velocity_reviewed = $source -match 'velocity-3\.5\.1-615\.jar' -and
        $source -match 'b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3' -and
        $source -match '18932366'
    bungee_2085_reviewed = $source -match 'BungeeCord/2085/artifact/bootstrap/target/BungeeCord\.jar' -and
        $source -match 'e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce' -and
        $source -match '25599274'
    no_ps7_only_operators = $source -notmatch '\?\?' -and $source -notmatch '\?\.' -and
        $source -notmatch 'ForEach-Object\s+-Parallel' -and $source -notmatch 'ConvertFrom-Json\s+-AsHashtable'
}
$failedStatic = @($staticChecks.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key)
if ($failedStatic.Count -ne 0) {
    throw "SERVER_MATRIX_PREPARER_STATIC_FAILED|$($failedStatic -join ',')"
}

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('mcace-server-matrix-fixture-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
$manifestFile = Join-Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))) 'build\runtime-assets\manifest.json'
$preparedManifestFile = Join-Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))) 'build\runtime-assets\prepared-manifest.json'
$manifestExisted = Test-Path -LiteralPath $manifestFile -PathType Leaf
$manifestHashBefore = if ($manifestExisted) {
    (Get-FileHash -LiteralPath $manifestFile -Algorithm SHA256).Hash
} else { '' }
$preparedManifestExisted = Test-Path -LiteralPath $preparedManifestFile -PathType Leaf
$preparedManifestHashBefore = if ($preparedManifestExisted) {
    (Get-FileHash -LiteralPath $preparedManifestFile -Algorithm SHA256).Hash
} else { '' }

function New-FillBuild(
        [int]$Id,
        [string]$Channel,
        [string]$Project,
        [string]$Version,
        [string]$Sha256,
        [long]$Size) {
    return [ordered]@{
        id = $Id
        channel = $Channel
        downloads = [ordered]@{
            'server:default' = [ordered]@{
                url = "https://fill-data.papermc.io/v1/objects/$Sha256/$Project-$Version-$Id.jar"
                checksums = [ordered]@{ sha256 = $Sha256 }
                size = $Size
            }
        }
    }
}

function Write-Fixture(
        [string]$Project,
        [string]$Version,
        [string]$Channel,
        [char]$HashCharacter,
        [int]$BaseId) {
    $oldHash = ([string]$HashCharacter) * 64
    $newCharacterCode = [int][char]$HashCharacter + 1
    if ($newCharacterCode -gt [int][char]'f') { $newCharacterCode = [int][char]'0' }
    $newHash = ([string][char]$newCharacterCode) * 64
    $fixture = @(
        (New-FillBuild $BaseId $Channel $Project $Version $oldHash (1000000 + $BaseId)),
        (New-FillBuild ($BaseId + 1) $Channel $Project $Version $newHash (1000001 + $BaseId))
    )
    [IO.File]::WriteAllText(
        (Join-Path $fixtureRoot "$Project-$Version.json"),
        ($fixture | ConvertTo-Json -Depth 8),
        [Text.UTF8Encoding]::new($false))
}

try {
    Write-Fixture 'paper' '1.21.11' 'STABLE' '0' 100
    Write-Fixture 'paper' '26.1.2' 'RECOMMENDED' '2' 200
    Write-Fixture 'paper' '26.2' 'STABLE' '4' 300
    Write-Fixture 'folia' '1.21.11' 'STABLE' '6' 400
    Write-Fixture 'folia' '26.1.2' 'RECOMMENDED' '8' 500
    Write-Fixture 'folia' '26.2' 'EXPERIMENTAL' 'a' 600

    $explicitRaw = (& $target -ReportOnly -MetadataFixtureDirectory $fixtureRoot | Out-String).Trim()
    $explicit = $explicitRaw | ConvertFrom-Json -ErrorAction Stop
    if ($explicit.schema -ne 'MCACE_SERVER_VERSION_MATRIX_PREPARER_REPORT_V1' -or
            $explicit.mode -ne 'REPORT_ONLY' -or $explicit.network_requested -or
            $explicit.write_requested -or $explicit.manifest_written -or
            -not $explicit.all_assets_resolved -or $explicit.resolved_asset_count -ne 8 -or
            @($explicit.assets).Count -ne 8) {
        throw 'SERVER_MATRIX_PREPARER_FIXTURE_REPORT_INVALID'
    }
    if (@($explicit.target_versions) -join ',' -cne '1.21.11,26.1.2,26.2') {
        throw 'SERVER_MATRIX_PREPARER_FIXTURE_TARGETS_INVALID'
    }
    $paper12111 = @($explicit.assets | Where-Object {
        $_.project -eq 'paper' -and $_.version -eq '1.21.11'
    })
    $folia262 = @($explicit.assets | Where-Object {
        $_.project -eq 'folia' -and $_.version -eq '26.2'
    })
    $bungee = @($explicit.assets | Where-Object { $_.project -eq 'bungeecord' })
    if ($paper12111.Count -ne 1 -or $paper12111[0].build -ne '101' -or
            $paper12111[0].java_major -ne 21 -or $folia262.Count -ne 1 -or
            $folia262[0].build -ne '601' -or $folia262[0].channel -ne 'EXPERIMENTAL' -or
            $folia262[0].java_major -ne 25 -or $bungee.Count -ne 1 -or
            $bungee[0].build -ne '2085' -or
            $bungee[0].sha256 -ne 'e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce') {
        throw 'SERVER_MATRIX_PREPARER_FIXTURE_SELECTION_INVALID'
    }
    if ($explicitRaw.IndexOf($fixtureRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $explicitRaw -match '(?i)"[^"\r\n]*(?:path|directory|root)[^"\r\n]*"\s*:') {
        throw 'SERVER_MATRIX_PREPARER_FIXTURE_PATH_DISCLOSURE'
    }

    $defaultRaw = (& $target -MetadataFixtureDirectory $fixtureRoot | Out-String).Trim()
    $default = $defaultRaw | ConvertFrom-Json -ErrorAction Stop
    if ($default.mode -ne 'REPORT_ONLY' -or $default.network_requested -or $default.write_requested -or
            $default.resolved_asset_count -ne 8) {
        throw 'SERVER_MATRIX_PREPARER_DEFAULT_NOT_READ_ONLY'
    }

    $manifestExistsAfter = Test-Path -LiteralPath $manifestFile -PathType Leaf
    if ($manifestExistsAfter -ne $manifestExisted) {
        throw 'SERVER_MATRIX_PREPARER_REPORT_ONLY_WROTE_MANIFEST'
    }
    if ($manifestExisted) {
        $manifestHashAfter = (Get-FileHash -LiteralPath $manifestFile -Algorithm SHA256).Hash
        if ($manifestHashAfter -cne $manifestHashBefore) {
            throw 'SERVER_MATRIX_PREPARER_REPORT_ONLY_CHANGED_MANIFEST'
        }
    }
    $preparedManifestExistsAfter = Test-Path -LiteralPath $preparedManifestFile -PathType Leaf
    if ($preparedManifestExistsAfter -ne $preparedManifestExisted) {
        throw 'SERVER_MATRIX_PREPARER_REPORT_ONLY_WROTE_PREPARED_MANIFEST'
    }
    if ($preparedManifestExisted) {
        $preparedManifestHashAfter = (Get-FileHash -LiteralPath $preparedManifestFile -Algorithm SHA256).Hash
        if ($preparedManifestHashAfter -cne $preparedManifestHashBefore) {
            throw 'SERVER_MATRIX_PREPARER_REPORT_ONLY_CHANGED_PREPARED_MANIFEST'
        }
    }

    $executeFixtureRejected = $false
    try {
        & $target -Execute -MetadataFixtureDirectory $fixtureRoot | Out-Null
    } catch {
        $executeFixtureRejected = $true
    }
    if (-not $executeFixtureRejected) {
        throw 'SERVER_MATRIX_PREPARER_EXECUTE_ACCEPTED_FIXTURE'
    }

    $registerFixtureRejected = $false
    try {
        & $target -RegisterPrepared -MetadataFixtureDirectory $fixtureRoot | Out-Null
    } catch {
        $registerFixtureRejected = $true
    }
    if (-not $registerFixtureRejected) {
        throw 'SERVER_MATRIX_PREPARER_REGISTER_ACCEPTED_METADATA_FIXTURE'
    }

    $badFixture = Join-Path $fixtureRoot 'paper-26.2.json'
    $badText = Get-Content -LiteralPath $badFixture -Raw
    $badText = $badText.Replace('https://fill-data.papermc.io/', 'https://example.invalid/')
    [IO.File]::WriteAllText($badFixture, $badText, [Text.UTF8Encoding]::new($false))
    $badRejected = $false
    try {
        & $target -ReportOnly -MetadataFixtureDirectory $fixtureRoot | Out-Null
    } catch {
        $badRejected = $_.Exception.Message -match 'SERVER_MATRIX_DOWNLOAD_ORIGIN_INVALID'
    }
    if (-not $badRejected) { throw 'SERVER_MATRIX_PREPARER_BAD_ORIGIN_NOT_REJECTED' }
} finally {
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$preparedFixtureRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('mcace-server-prepared-fixture-' + [Guid]::NewGuid().ToString('N'))
$preparedFixtureScript = Join-Path $preparedFixtureRoot 'scripts\prepare-server-version-matrix.ps1'
$preparedFixtureAssets = Join-Path $preparedFixtureRoot 'build\runtime-assets'
$junctionPath = $null
try {
    New-Item -ItemType Directory -Path (Split-Path -Parent $preparedFixtureScript) -Force | Out-Null
    New-Item -ItemType Directory -Path $preparedFixtureAssets -Force | Out-Null
    Copy-Item -LiteralPath $target -Destination $preparedFixtureScript

    $serverSpecs = @(
        [pscustomobject]@{ project = 'paper'; version = '1.21.11'; build = '101'; java = 21; channel = 'STABLE' },
        [pscustomobject]@{ project = 'paper'; version = '26.1.2'; build = '201'; java = 25; channel = 'STABLE' },
        [pscustomobject]@{ project = 'paper'; version = '26.2'; build = '301'; java = 25; channel = 'STABLE' },
        [pscustomobject]@{ project = 'folia'; version = '1.21.11'; build = '401'; java = 21; channel = 'STABLE' },
        [pscustomobject]@{ project = 'folia'; version = '26.1.2'; build = '501'; java = 25; channel = 'STABLE' },
        [pscustomobject]@{ project = 'folia'; version = '26.2'; build = '601'; java = 25; channel = 'BETA' }
    )
    $frozenAssets = [Collections.Generic.List[object]]::new()
    foreach ($spec in $serverSpecs) {
        $buildRoot = Join-Path $preparedFixtureAssets (Join-Path $spec.project `
            (Join-Path $spec.version $spec.build))
        New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null
        $serverFile = Join-Path $buildRoot 'server.jar'
        [IO.File]::WriteAllText(
            $serverFile,
            "server|$($spec.project)|$($spec.version)|$($spec.build)",
            [Text.UTF8Encoding]::new($false))
        $serverItem = Get-Item -LiteralPath $serverFile
        $serverSha = (Get-FileHash -LiteralPath $serverFile -Algorithm SHA256).Hash.ToLowerInvariant()
        [void]$frozenAssets.Add([pscustomobject][ordered]@{
            project = $spec.project
            version = $spec.version
            build = $spec.build
            url = "https://fill-data.papermc.io/v1/objects/$serverSha/$($spec.project)-$($spec.version)-$($spec.build).jar"
            sha256 = $serverSha
            size = [long]$serverItem.Length
            channel = $spec.channel
            java_major = [int]$spec.java
        })

        $preparedRoot = Join-Path $buildRoot 'prepared'
        $cacheRoot = Join-Path $preparedRoot 'cache'
        $libraryRoot = Join-Path $preparedRoot 'libraries\example'
        $versionRoot = Join-Path $preparedRoot (Join-Path 'versions' $spec.version)
        New-Item -ItemType Directory -Path $cacheRoot, $libraryRoot, $versionRoot -Force | Out-Null
        [IO.File]::WriteAllText(
            (Join-Path $cacheRoot "mojang-$($spec.version).jar"),
            "cache|$($spec.project)|$($spec.version)",
            [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText(
            (Join-Path $libraryRoot "$($spec.project)-$($spec.version).jar"),
            "library|$($spec.project)|$($spec.version)",
            [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText(
            (Join-Path $versionRoot "$($spec.project)-server.jar"),
            "version|$($spec.project)|$($spec.version)",
            [Text.UTF8Encoding]::new($false))
    }
    [void]$frozenAssets.Add([pscustomobject][ordered]@{
        project = 'velocity'
        version = '3.5.1-615'
        build = '615'
        url = 'https://fill-data.papermc.io/v1/objects/b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3/velocity-3.5.1-615.jar'
        sha256 = 'b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3'
        size = 18932366
        channel = 'REVIEWED'
        java_major = 21
        target_versions = @('1.21.11', '26.1.2', '26.2')
    })
    [void]$frozenAssets.Add([pscustomobject][ordered]@{
        project = 'bungeecord'
        version = '2085'
        build = '2085'
        url = 'https://hub.spigotmc.org/jenkins/job/BungeeCord/2085/artifact/bootstrap/target/BungeeCord.jar'
        sha256 = 'e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce'
        size = 25599274
        channel = 'REVIEWED'
        java_major = 21
        target_versions = @('1.21.11', '26.1.2', '26.2')
    })
    $frozenFixture = [pscustomobject][ordered]@{
        schema = 'MCACE_SERVER_VERSION_MATRIX_ASSETS_V1'
        generated_at = '2026-08-14T00:00:00.0000000+00:00'
        prepared_tree_status = 'DEFERRED'
        assets = @($frozenAssets)
    }
    [IO.File]::WriteAllText(
        (Join-Path $preparedFixtureAssets 'manifest.json'),
        ($frozenFixture | ConvertTo-Json -Depth 20),
        [Text.UTF8Encoding]::new($false))

    $registerRaw = (& $preparedFixtureScript -RegisterPrepared | Out-String).Trim()
    $register = $registerRaw | ConvertFrom-Json -ErrorAction Stop
    if ($register.mode -cne 'REGISTER_PREPARED' -or $register.network_requested -or
            -not $register.write_requested -or -not $register.prepared_manifest_written -or
            $register.prepared_tree_status -cne 'VERIFIED' -or
            $register.prepared_verified_count -ne 6 -or -not $register.all_prepared_trees_verified) {
        throw 'SERVER_MATRIX_PREPARED_REGISTER_REPORT_INVALID'
    }
    $preparedFixtureManifest = Join-Path $preparedFixtureAssets 'prepared-manifest.json'
    $preparedRaw = Get-Content -LiteralPath $preparedFixtureManifest -Raw
    $prepared = $preparedRaw | ConvertFrom-Json -ErrorAction Stop
    if ($prepared.schema -cne 'MCACE_SERVER_VERSION_MATRIX_PREPARED_V1' -or
            (@($prepared.roots) -join ',') -cne 'cache,libraries,versions' -or
            @($prepared.trees).Count -ne 6 -or
            $preparedRaw.IndexOf($preparedFixtureRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw 'SERVER_MATRIX_PREPARED_MANIFEST_INVALID'
    }
    foreach ($tree in @($prepared.trees)) {
        if (@($tree.files).Count -ne 3) { throw 'SERVER_MATRIX_PREPARED_FIXTURE_FILE_COUNT_INVALID' }
        foreach ($file in @($tree.files)) {
            if ($file.relative -notmatch '^(cache|libraries|versions)/' -or
                    $file.relative.IndexOf('\') -ge 0 -or $file.relative -match '^[A-Za-z]:' -or
                    $file.sha256 -notmatch '^[0-9a-f]{64}$' -or [long]$file.size -lt 0L) {
                throw 'SERVER_MATRIX_PREPARED_FIXTURE_RELATIVE_INVALID'
            }
        }
    }

    $preparedHashBeforeReport = (Get-FileHash -LiteralPath $preparedFixtureManifest -Algorithm SHA256).Hash
    $preparedReportRaw = (& $preparedFixtureScript -ReportOnly | Out-String).Trim()
    $preparedReport = $preparedReportRaw | ConvertFrom-Json -ErrorAction Stop
    $preparedHashAfterReport = (Get-FileHash -LiteralPath $preparedFixtureManifest -Algorithm SHA256).Hash
    if ($preparedReport.mode -cne 'REPORT_ONLY' -or $preparedReport.network_requested -or
            $preparedReport.write_requested -or $preparedReport.prepared_tree_status -cne 'VERIFIED' -or
            $preparedReport.prepared_verified_count -ne 6 -or
            @($preparedReport.prepared_trees | Where-Object { $_.status -cne 'VERIFIED' }).Count -ne 0 -or
            $preparedHashAfterReport -cne $preparedHashBeforeReport) {
        throw 'SERVER_MATRIX_PREPARED_REPORT_RECOMPUTE_INVALID'
    }

    $firstSpec = $serverSpecs[0]
    $firstPrepared = Join-Path $preparedFixtureAssets (Join-Path $firstSpec.project `
        (Join-Path $firstSpec.version (Join-Path $firstSpec.build 'prepared')))
    $extraFile = Join-Path $firstPrepared 'libraries\example\unexpected.jar'
    [IO.File]::WriteAllText($extraFile, 'unexpected', [Text.UTF8Encoding]::new($false))
    $extraRejected = $false
    try { & $preparedFixtureScript -ReportOnly | Out-Null } catch {
        $extraRejected = $_.Exception.Message -match 'SERVER_MATRIX_PREPARED_TREE_CONTENT_MISMATCH'
    }
    Remove-Item -LiteralPath $extraFile -Force
    if (-not $extraRejected) { throw 'SERVER_MATRIX_PREPARED_UNKNOWN_FILE_NOT_REJECTED' }

    $cacheRoot = Join-Path $firstPrepared 'cache'
    $cacheAway = Join-Path $firstPrepared 'cache-fixture-missing'
    Move-Item -LiteralPath $cacheRoot -Destination $cacheAway
    $missingRejected = $false
    try { & $preparedFixtureScript -ReportOnly | Out-Null } catch {
        $missingRejected = $_.Exception.Message -match 'SERVER_MATRIX_PREPARED_DIRECTORY_MISSING'
    } finally {
        Move-Item -LiteralPath $cacheAway -Destination $cacheRoot
    }
    if (-not $missingRejected) { throw 'SERVER_MATRIX_PREPARED_MISSING_ROOT_NOT_REJECTED' }

    $badPrepared = Get-Content -LiteralPath $preparedFixtureManifest -Raw | ConvertFrom-Json
    $badPrepared.trees[0].files[0].relative = 'config/unknown.jar'
    [IO.File]::WriteAllText(
        $preparedFixtureManifest,
        ($badPrepared | ConvertTo-Json -Depth 20),
        [Text.UTF8Encoding]::new($false))
    $unknownRootRejected = $false
    try { & $preparedFixtureScript -ReportOnly | Out-Null } catch {
        $unknownRootRejected = $_.Exception.Message -match 'SERVER_MATRIX_PREPARED_RELATIVE_INVALID'
    }
    if (-not $unknownRootRejected) { throw 'SERVER_MATRIX_PREPARED_UNKNOWN_ROOT_NOT_REJECTED' }
    & $preparedFixtureScript -RegisterPrepared | Out-Null

    $badPrepared = Get-Content -LiteralPath $preparedFixtureManifest -Raw | ConvertFrom-Json
    $badPrepared.trees[0] | Add-Member -MemberType NoteProperty -Name unknown_field -Value 'reject-me'
    [IO.File]::WriteAllText(
        $preparedFixtureManifest,
        ($badPrepared | ConvertTo-Json -Depth 20),
        [Text.UTF8Encoding]::new($false))
    $unknownFieldRejected = $false
    try { & $preparedFixtureScript -ReportOnly | Out-Null } catch {
        $unknownFieldRejected = $_.Exception.Message -match 'SERVER_MATRIX_PREPARED_MANIFEST_TREE_INVALID'
    }
    if (-not $unknownFieldRejected) { throw 'SERVER_MATRIX_PREPARED_UNKNOWN_FIELD_NOT_REJECTED' }
    & $preparedFixtureScript -RegisterPrepared | Out-Null

    if ([IO.Path]::DirectorySeparatorChar -eq '\') {
        $junctionTarget = Join-Path $preparedFixtureRoot 'junction-target'
        New-Item -ItemType Directory -Path $junctionTarget | Out-Null
        [IO.File]::WriteAllText(
            (Join-Path $junctionTarget 'outside.jar'),
            'outside',
            [Text.UTF8Encoding]::new($false))
        $junctionPath = Join-Path $firstPrepared 'libraries\fixture-junction'
        New-Item -ItemType Junction -Path $junctionPath -Target $junctionTarget -ErrorAction Stop | Out-Null
        $reparseRejected = $false
        try { & $preparedFixtureScript -ReportOnly | Out-Null } catch {
            $reparseRejected = $_.Exception.Message -match 'SERVER_MATRIX_PREPARED_REPARSE_POINT'
        }
        [IO.Directory]::Delete($junctionPath)
        $junctionPath = $null
        if (-not $reparseRejected) { throw 'SERVER_MATRIX_PREPARED_REPARSE_NOT_REJECTED' }
    }

    $finalReport = (& $preparedFixtureScript -ReportOnly | Out-String).Trim() | ConvertFrom-Json
    if ($finalReport.prepared_verified_count -ne 6 -or
            $finalReport.prepared_tree_status -cne 'VERIFIED') {
        throw 'SERVER_MATRIX_PREPARED_FINAL_REPORT_INVALID'
    }
} finally {
    if ($null -ne $junctionPath -and (Test-Path -LiteralPath $junctionPath)) {
        [IO.Directory]::Delete($junctionPath)
    }
    $fullPreparedFixtureRoot = [IO.Path]::GetFullPath($preparedFixtureRoot)
    $fullTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char[]]@('\', '/')) +
        [IO.Path]::DirectorySeparatorChar
    if (-not $fullPreparedFixtureRoot.StartsWith($fullTempRoot, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $fullPreparedFixtureRoot) -notlike 'mcace-server-prepared-fixture-*') {
        throw 'SERVER_MATRIX_PREPARED_FIXTURE_CLEANUP_GUARD'
    }
    Remove-Item -LiteralPath $fullPreparedFixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
}

[Console]::Out.WriteLine('{"schema":1,"tool":"server-version-matrix-preparer-tests","status":"passed"}')
