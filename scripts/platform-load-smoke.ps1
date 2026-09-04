[CmdletBinding(DefaultParameterSetName = 'Execute')]
param(
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidateSet('1.21.11', '26.1.2', '26.2')]
    [string]$FabricTarget,
    [Parameter(ParameterSetName = 'Execute')]
    [switch]$WithFabricClient,
    [Parameter(ParameterSetName = 'Execute')]
    [switch]$WithFabricEvidence,
    [Parameter(ParameterSetName = 'Execute')]
    [ValidatePattern('^[A-Za-z0-9_]{3,16}$')]
    [string]$FabricEvidencePlayerName,
    [Parameter(ParameterSetName = 'Execute')]
    [switch]$RetainDiagnostics,
    [Parameter(ParameterSetName = 'Execute')]
    [ValidateRange(30, 600)]
    [int]$ManualConsentTimeoutSeconds = 120,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [switch]$ReportOnly,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedFabricArtifactSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedVelocityPluginSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPaperPluginSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedVelocityServerSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPaperServerSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPaperPreparedManifestSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPaperPreparedTreeSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedFabricVersionInfoSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedFabricAssetIndexSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedFabricAssetObjectManifestSha256,
    [ValidateRange(1, 1440)]
    [int]$MaximumReportAgeMinutes = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-SmokeRunToken([string]$RunToken) {
    if ($RunToken -cnotmatch '^[0-9a-f]{32}$') {
        throw 'PLATFORM_SMOKE_CSPRNG_RUN_TOKEN_REQUIRED'
    }
}

function New-SmokeRunToken {
    $bytes = [byte[]]::new(16)
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) }
    finally { $generator.Dispose() }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

function Test-ExactRunTokenArgument([string]$CommandLine, [string]$RunToken) {
    Assert-SmokeRunToken $RunToken
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $false }
    $argument = "-Dmcace.smoke.run-token=$RunToken"
    $pattern = '(?:^|\s)(?:"{0}"|{0})(?=$|\s)' -f [regex]::Escape($argument)
    return [regex]::IsMatch(
        $CommandLine, $pattern, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
}

if ($WithFabricEvidence) {
    $WithFabricClient = $true
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$executedScriptSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$buildRoot = Join-Path $repoRoot 'build'
$smokeRoot = Join-Path $buildRoot 'platform-smoke'
$cacheRoot = Join-Path $smokeRoot 'cache'
$runsRoot = Join-Path $smokeRoot 'runs'
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
$runToken = New-SmokeRunToken
Assert-SmokeRunToken $runToken
$runTokenJvmArgument = "-Dmcace.smoke.run-token=$runToken"
$runLeaf = '{0}-{1}-{2}' -f $runId, $FabricTarget.Replace('.', '_'), $runToken
$runRoot = Join-Path $runsRoot $runLeaf
$velocityRoot = Join-Path $runRoot 'velocity'
$paperRoot = Join-Path $runRoot 'paper'
$manualConsentHandshakeTimeoutSeconds = if ($WithFabricEvidence) {
    # The client-side GUI decision budget is deliberately capped at the same
    # 300-second product ceiling as the proxy contract.  The parameter accepts
    # a wider range for backwards-compatible callers, but every downstream
    # wait, report, and Gradle property uses this effective value.
    [Math]::Min(300, [Math]::Max(30, [int]$ManualConsentTimeoutSeconds))
} else {
    30
}
# The proxy starts its handshake clock before the client can render the prompt,
# exchange the screenshot/attestation, scan the local manifest, and send AUTH.
# Reserve a bounded 30-second pre-auth margin for the evidence path while
# keeping the server-side value inside the 2..300-second admission contract.
$serverHandshakeSafetyMarginSeconds = if ($WithFabricEvidence) { 30 } else { 0 }
$velocityHandshakeTimeoutSeconds = [Math]::Min(
    300, $manualConsentHandshakeTimeoutSeconds + $serverHandshakeSafetyMarginSeconds)
$gradleVersion = '9.6.1'
$reportSchema = 8
$bindingSchema = 'MCACE_FABRIC_GUI_EVIDENCE_BINDING_V6'
$fabricArtifactClass = 'sanitized-final-fabric-gui-evidence'
$fabricArtifactVersion = '0.1.0-SNAPSHOT'
$fabricSmokeBuildId = "platform-smoke-$runId"
$fabricExpectedArtifactMarker = ''
$velocityPlugin = Join-Path $repoRoot 'mcace-server-velocity\build\libs\mcace-server-velocity-0.1.0-SNAPSHOT.jar'
$paperPlugin = Join-Path $repoRoot 'mcace-server-paper\build\libs\mcace-server-paper-0.1.0-SNAPSHOT.jar'
$serverMatrixRoot = Join-Path $repoRoot 'build\runtime-assets'
$serverMatrixManifest = Join-Path $serverMatrixRoot 'manifest.json'
$serverPreparedManifest = Join-Path $serverMatrixRoot 'prepared-manifest.json'
$stagedModernDependencies = Join-Path $repoRoot 'build\fabric-modern-deps'

$fabricTargets = [ordered]@{
    '1.21.11' = [ordered]@{
        minecraft_version = '1.21.11'
        fabric_api_version = '0.141.6+1.21.11'
        java_major = 21
        artifact_kind = 'FINAL_REMAP_JAR'
        runtime_mode = 'LOOM_FINAL_REMAP_ARTIFACT'
        runtime_artifact_kind = 'NAMED_SMOKE_JAR'
        project_directory = Join-Path $repoRoot 'mcace-client-fabric'
        gradle_project_directory = $repoRoot
        build_task = ':mcace-client-fabric:remapJar'
        verify_task = ':mcace-client-fabric:verifySmokeArtifactMode'
        run_task = ':mcace-client-fabric:runClient'
        artifact_path = Join-Path $repoRoot 'mcace-client-fabric\build\libs\mcace-client-fabric-0.1.0-SNAPSHOT.jar'
        runtime_artifact_path = Join-Path $repoRoot 'mcace-client-fabric\build\smoke-libs\mcace-client-fabric-0.1.0-SNAPSHOT-smoke-named.jar'
        asset_index = '29'
        version_info_sha1 = '6b6c2d7f875539647774da3e334b27d0a67331a4'
        version_info_sha256 = 'bd39d85072a5bc178f5407a99db783fbe8dfdda85261d25287bb276224c4a47e'
        asset_index_sha1 = '7c7f5df63dfd676251babde8fd2b05af54ca77dd'
        asset_index_size = 529966L
        paper_build = '132'
        paper_sha256 = '5ffef465eeeb5f2a3c23a24419d97c51afd7dbb4923ff42df9a3f58bba1ccfba'
        paper_size = 54846016L
    }
    '26.1.2' = [ordered]@{
        minecraft_version = '26.1.2'
        fabric_api_version = '0.155.2+26.1.2'
        java_major = 25
        artifact_kind = 'FINAL_NAMED_JAR'
        runtime_mode = 'LOOM_FINAL_NAMED_JAR_ARTIFACT'
        runtime_artifact_kind = 'FINAL_NAMED_JAR'
        project_directory = Join-Path $repoRoot 'fabric-modern\client-26.1.2'
        gradle_project_directory = Join-Path $repoRoot 'fabric-modern'
        build_task = ':client-26.1.2:jar'
        verify_task = ':client-26.1.2:verifySmokeArtifactMode'
        run_task = ':client-26.1.2:runClient'
        artifact_path = Join-Path $repoRoot 'fabric-modern\client-26.1.2\build\libs\mcace-client-fabric-26.1.2-0.1.0-SNAPSHOT.jar'
        runtime_artifact_path = Join-Path $repoRoot 'fabric-modern\client-26.1.2\build\libs\mcace-client-fabric-26.1.2-0.1.0-SNAPSHOT.jar'
        asset_index = '30'
        version_info_sha1 = '09c3ffc1d9d1182a1083a868595d98f22687e5d5'
        version_info_sha256 = '2a19d93dc404c4f3d9ebedc437ab3b11c5a272b41c45d74266a64005125b0a72'
        asset_index_sha1 = '1c325980cb885aabe2602f94993eb2d82dd44a82'
        asset_index_size = 548391L
        paper_build = '74'
        paper_sha256 = '1d70b1dab9cf4a6de615209a536f3a45a2186240253c428213ce2188ab95e5f7'
        paper_size = 52893229L
    }
    '26.2' = [ordered]@{
        minecraft_version = '26.2'
        fabric_api_version = '0.157.0+26.2'
        java_major = 25
        artifact_kind = 'FINAL_NAMED_JAR'
        runtime_mode = 'LOOM_FINAL_NAMED_JAR_ARTIFACT'
        runtime_artifact_kind = 'FINAL_NAMED_JAR'
        project_directory = Join-Path $repoRoot 'fabric-modern\client-26.2'
        gradle_project_directory = Join-Path $repoRoot 'fabric-modern'
        build_task = ':client-26.2:jar'
        verify_task = ':client-26.2:verifySmokeArtifactMode'
        run_task = ':client-26.2:runClient'
        artifact_path = Join-Path $repoRoot 'fabric-modern\client-26.2\build\libs\mcace-client-fabric-26.2-0.1.0-SNAPSHOT.jar'
        runtime_artifact_path = Join-Path $repoRoot 'fabric-modern\client-26.2\build\libs\mcace-client-fabric-26.2-0.1.0-SNAPSHOT.jar'
        asset_index = '32'
        version_info_sha1 = 'ef815ab76bce3f1a4c2d7fe712527304923bbe3a'
        version_info_sha256 = 'c09c6d5d17181cd1827665946452781668da2d84a98f4bff38a1f63dc332c15d'
        asset_index_sha1 = 'c12254a593cdebaf8e8102250a71d8f40124a0b5'
        asset_index_size = 586366L
        paper_build = '116'
        paper_sha256 = '17eee738bc0f6b747646be4199672c4efcb2084efd7e291ec5254a45d5ae6f2e'
        paper_size = 64426830L
    }
}
$fabricDescriptor = $fabricTargets[$FabricTarget]
if ($null -eq $fabricDescriptor) { throw 'PLATFORM_SMOKE_FABRIC_TARGET_INVALID' }
$fabricRuntimeMode = [string]$fabricDescriptor.runtime_mode
$fabricArtifactJar = [string]$fabricDescriptor.artifact_path
$fabricRuntimeArtifactJar = [string]$fabricDescriptor.runtime_artifact_path
$preparedPaperRoot = ''

$velocityArtifact = @{
    Name = 'velocity-3.5.1-615.jar'
    Url = 'https://fill-data.papermc.io/v1/objects/b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3/velocity-3.5.1-615.jar'
    Sha256 = 'b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3'
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-Sha1([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA1).Hash.ToLowerInvariant()
}

function Get-ObjectProperty([object]$Value, [string]$Name) {
    if ($null -eq $Value) { return $null }
    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Resolve-ServerMatrixAssets {
    if (-not (Test-Path -LiteralPath $serverMatrixManifest -PathType Leaf)) {
        throw 'PLATFORM_SMOKE_SERVER_MATRIX_MANIFEST_REQUIRED'
    }
    $manifestPath = Assert-DirectLocalPath $serverMatrixManifest
    try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'PLATFORM_SMOKE_SERVER_MATRIX_MANIFEST_INVALID' }
    if ($manifest.schema -cne 'MCACE_SERVER_VERSION_MATRIX_ASSETS_V1' -or
            @($manifest.assets).Count -ne 8) {
        throw 'PLATFORM_SMOKE_SERVER_MATRIX_MANIFEST_INVALID'
    }
    $velocity = @($manifest.assets | Where-Object {
        $_.project -ceq 'velocity' -and $_.version -ceq '3.5.1-615'
    })
    $paper = @($manifest.assets | Where-Object {
        $_.project -ceq 'paper' -and $_.version -ceq $FabricTarget
    })
    if ($velocity.Count -ne 1 -or $paper.Count -ne 1) {
        throw 'PLATFORM_SMOKE_SERVER_MATRIX_TARGET_ASSET_REQUIRED'
    }
    foreach ($asset in @($velocity[0], $paper[0])) {
        $sha256 = [string](Get-ObjectProperty $asset 'sha256')
        $size = Get-ObjectProperty $asset 'size'
        $url = [string](Get-ObjectProperty $asset 'url')
        if ($sha256 -cnotmatch '^[0-9a-f]{64}$' -or $null -eq $size -or
                [Convert]::ToInt64($size) -le 0L) {
            throw 'PLATFORM_SMOKE_SERVER_MATRIX_ASSET_IDENTITY_INVALID'
        }
        $urlMatch = [regex]::Match(
            $url,
            '^https://fill-data\.papermc\.io/v1/objects/(?<sha>[0-9a-f]{64})/[^/?#]+$')
        if (-not $urlMatch.Success -or $urlMatch.Groups['sha'].Value -cne $sha256) {
            throw 'PLATFORM_SMOKE_SERVER_MATRIX_ASSET_ORIGIN_INVALID'
        }
    }
    if ($velocity[0].sha256 -cne $velocityArtifact.Sha256 -or
            $velocity[0].url -cne $velocityArtifact.Url) {
        throw 'PLATFORM_SMOKE_REVIEWED_VELOCITY_IDENTITY_INVALID'
    }
    if ([string]$paper[0].build -cne [string]$fabricDescriptor.paper_build -or
            [string]$paper[0].sha256 -cne [string]$fabricDescriptor.paper_sha256 -or
            [long]$paper[0].size -ne [long]$fabricDescriptor.paper_size -or
            [string]$paper[0].channel -cne 'STABLE' -or
            [int]$paper[0].java_major -ne [int]$fabricDescriptor.java_major) {
        throw 'PLATFORM_SMOKE_TARGET_PAPER_IDENTITY_INVALID'
    }
    $velocityPath = Join-Path $serverMatrixRoot 'velocity\3.5.1-615\server.jar'
    $paperDirectory = Join-Path $serverMatrixRoot (
        'paper\{0}\{1}' -f $FabricTarget, [string]$fabricDescriptor.paper_build)
    return [pscustomobject]@{
        manifest_path = $manifestPath
        manifest_sha256 = Get-Sha256 $manifestPath
        velocity = [ordered]@{
            Name = 'velocity-3.5.1-615.jar'
            Url = [string]$velocity[0].url
            Sha256 = [string]$velocity[0].sha256
            Size = [Convert]::ToInt64($velocity[0].size)
            Path = $velocityPath
        }
        paper = [ordered]@{
            Name = "paper-$FabricTarget-$($paper[0].build).jar"
            Url = [string]$paper[0].url
            Sha256 = [string]$paper[0].sha256
            Size = [Convert]::ToInt64($paper[0].size)
            Path = Join-Path $paperDirectory 'server.jar'
            Build = [string]$paper[0].build
        }
        prepared_root = Join-Path $paperDirectory 'prepared'
    }
}

function Assert-FabricAssetCache([bool]$Required = $true) {
    if (-not $Required) {
        return [ordered]@{
            fabric_asset_cache_verified = $false
            fabric_version_info_sha1 = [string]$fabricDescriptor.version_info_sha1
            fabric_version_info_sha256 = [string]$fabricDescriptor.version_info_sha256
            fabric_asset_index_id = [string]$fabricDescriptor.asset_index
            fabric_asset_index_sha1 = [string]$fabricDescriptor.asset_index_sha1
            fabric_asset_index_sha256 = ''
            fabric_asset_index_size = [long]$fabricDescriptor.asset_index_size
            fabric_asset_object_manifest_sha256 = ''
            fabric_asset_object_count = 0
            fabric_asset_object_total_size = 0L
        }
    }
    $gradleUserRoot = if (-not [string]::IsNullOrWhiteSpace($env:GRADLE_USER_HOME)) {
        $env:GRADLE_USER_HOME
    } elseif (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        Join-Path $env:USERPROFILE '.gradle'
    } else {
        throw 'PLATFORM_SMOKE_GRADLE_USER_HOME_REQUIRED'
    }
    $loomCache = Assert-DirectLocalPath (Join-Path $gradleUserRoot 'caches\fabric-loom') -Directory
    $versionInfoPath = Assert-DirectLocalPath (Join-Path $loomCache (
        '{0}\mojang_minecraft_info.json' -f [string]$fabricDescriptor.minecraft_version))
    if ((Get-Sha1 $versionInfoPath) -cne [string]$fabricDescriptor.version_info_sha1 -or
            (Get-Sha256 $versionInfoPath) -cne [string]$fabricDescriptor.version_info_sha256) {
        throw "PLATFORM_SMOKE_FABRIC_VERSION_INFO_PIN_MISMATCH: $FabricTarget"
    }
    try { $versionInfo = Get-Content -LiteralPath $versionInfoPath -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'PLATFORM_SMOKE_FABRIC_VERSION_INFO_INVALID' }
    $assetIndex = $versionInfo.assetIndex
    if ([string]$versionInfo.id -cne [string]$fabricDescriptor.minecraft_version -or
            [int]$versionInfo.javaVersion.majorVersion -ne [int]$fabricDescriptor.java_major -or
            $null -eq $assetIndex -or
            [string]$assetIndex.id -cne [string]$fabricDescriptor.asset_index -or
            [string]$assetIndex.sha1 -cne [string]$fabricDescriptor.asset_index_sha1 -or
            [long]$assetIndex.size -ne [long]$fabricDescriptor.asset_index_size) {
        throw 'PLATFORM_SMOKE_FABRIC_ASSET_INDEX_IDENTITY_INVALID'
    }
    $indexUrlPattern = '^https://piston-meta\.mojang\.com/v1/packages/{0}/{1}\.json$' -f
        [regex]::Escape([string]$assetIndex.sha1), [regex]::Escape([string]$assetIndex.id)
    if ([string]$assetIndex.url -cnotmatch $indexUrlPattern) {
        throw 'PLATFORM_SMOKE_FABRIC_ASSET_INDEX_ORIGIN_INVALID'
    }
    $indexFileName = '{0}-{1}.json' -f [string]$fabricDescriptor.minecraft_version, [string]$assetIndex.id
    $indexPath = Join-Path $loomCache (Join-Path 'assets\indexes' $indexFileName)
    if (-not (Test-Path -LiteralPath $indexPath -PathType Leaf)) {
        throw "PLATFORM_SMOKE_FABRIC_ASSET_INDEX_CACHE_REQUIRED: $FabricTarget"
    }
    $indexPath = Assert-DirectLocalPath $indexPath
    if ((Get-Item -LiteralPath $indexPath).Length -ne [long]$assetIndex.size -or
            (Get-Sha1 $indexPath) -cne [string]$assetIndex.sha1) {
        throw 'PLATFORM_SMOKE_FABRIC_ASSET_INDEX_CACHE_INVALID'
    }
    try { $index = Get-Content -LiteralPath $indexPath -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'PLATFORM_SMOKE_FABRIC_ASSET_INDEX_JSON_INVALID' }
    $objects = @($index.objects.PSObject.Properties)
    if ($objects.Count -eq 0) { throw 'PLATFORM_SMOKE_FABRIC_ASSET_OBJECTS_REQUIRED' }
    $seen = [System.Collections.Generic.Dictionary[string,long]]::new([StringComparer]::Ordinal)
    $manifestEntries = [System.Collections.Generic.List[string]]::new()
    $totalSize = 0L
    foreach ($property in $objects) {
        $hash = [string]$property.Value.hash
        $size = [long]$property.Value.size
        if ($hash -cnotmatch '^[0-9a-f]{40}$' -or $size -le 0L) {
            throw 'PLATFORM_SMOKE_FABRIC_ASSET_OBJECT_IDENTITY_INVALID'
        }
        if ($seen.ContainsKey($hash)) {
            if ($seen[$hash] -ne $size) {
                throw 'PLATFORM_SMOKE_FABRIC_ASSET_OBJECT_DUPLICATE_INVALID'
            }
            continue
        }
        $seen.Add($hash, $size)
        $objectPath = Join-Path $loomCache ('assets\objects\{0}\{1}' -f $hash.Substring(0, 2), $hash)
        if (-not (Test-Path -LiteralPath $objectPath -PathType Leaf)) {
            throw "PLATFORM_SMOKE_FABRIC_ASSET_OBJECT_CACHE_REQUIRED: $FabricTarget"
        }
        $objectPath = Assert-DirectLocalPath $objectPath
        if ((Get-Item -LiteralPath $objectPath).Length -ne $size -or
                (Get-Sha1 $objectPath) -cne $hash) {
            throw 'PLATFORM_SMOKE_FABRIC_ASSET_OBJECT_CACHE_INVALID'
        }
        $manifestEntries.Add("$hash|$size")
        $totalSize += $size
    }
    return [ordered]@{
        fabric_asset_cache_verified = $true
        fabric_version_info_sha1 = Get-Sha1 $versionInfoPath
        fabric_version_info_sha256 = Get-Sha256 $versionInfoPath
        fabric_asset_index_id = [string]$assetIndex.id
        fabric_asset_index_sha1 = Get-Sha1 $indexPath
        fabric_asset_index_sha256 = Get-Sha256 $indexPath
        fabric_asset_index_size = [long](Get-Item -LiteralPath $indexPath).Length
        fabric_asset_object_manifest_sha256 = Get-ManifestSha256 $manifestEntries.ToArray()
        fabric_asset_object_count = [int]$manifestEntries.Count
        fabric_asset_object_total_size = $totalSize
    }
}

function Assert-DirectLocalPath([string]$Path, [switch]$Directory) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [System.IO.Path]::IsPathRooted($Path)) {
        throw 'PLATFORM_SMOKE_ABSOLUTE_LOCAL_PATH_REQUIRED'
    }
    $item = Get-Item -LiteralPath ([System.IO.Path]::GetFullPath($Path)) -Force -ErrorAction Stop
    if ($Directory -and -not $item.PSIsContainer) { throw 'PLATFORM_SMOKE_DIRECTORY_REQUIRED' }
    if (-not $Directory -and $item.PSIsContainer) { throw 'PLATFORM_SMOKE_FILE_REQUIRED' }
    if ($item.PSDrive.DisplayRoot -or $item.PSDrive.Root.StartsWith('\\')) {
        throw 'PLATFORM_SMOKE_FIXED_LOCAL_DRIVE_REQUIRED'
    }
    $cursorPath = $item.FullName
    while (-not [string]::IsNullOrWhiteSpace($cursorPath)) {
        $cursor = Get-Item -LiteralPath $cursorPath -Force -ErrorAction Stop
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'PLATFORM_SMOKE_REPARSE_PATH_REJECTED'
        }
        $parentPath = Split-Path -Path $cursorPath -Parent
        if ([string]::IsNullOrWhiteSpace($parentPath) -or $parentPath -eq $cursorPath) { break }
        $cursorPath = $parentPath
    }
    return $item.FullName
}

function Set-ExactVelocityPolicyTuple(
        [string]$ConfigPath,
        [ValidateSet('1.21.11', '26.1.2', '26.2')]
        [string]$MinecraftVersion,
        [string]$ClientBuildId) {
    if ($ClientBuildId -cnotmatch '^platform-smoke-[0-9]{8}T[0-9]{9}Z$') {
        throw 'PLATFORM_SMOKE_VELOCITY_POLICY_BUILD_ID_INVALID'
    }
    $resolvedConfig = Assert-DirectLocalPath $ConfigPath
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $configuration = [System.IO.File]::ReadAllText($resolvedConfig, $strictUtf8)
    $options = [System.Text.RegularExpressions.RegexOptions]::Multiline -bor
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    $values = [ordered]@{
        'policy.minecraft-versions' = $MinecraftVersion
        'policy.client-build-ids' = $ClientBuildId
    }
    foreach ($key in @($values.Keys)) {
        $keyPattern = '^[\t ]*{0}(?:(?:[\t ]*(?:=|:)[\t ]*)|[\t ]+)[^\r\n]*(?=\r?$)' -f
            [regex]::Escape($key)
        $matches = [regex]::Matches($configuration, $keyPattern, $options)
        if ($matches.Count -ne 1) {
            throw "PLATFORM_SMOKE_VELOCITY_POLICY_KEY_COUNT_INVALID: $key"
        }
        $configuration = [regex]::Replace(
            $configuration, $keyPattern, "$key=$($values[$key])", $options)
    }
    [System.IO.File]::WriteAllText(
        $resolvedConfig, $configuration, [System.Text.UTF8Encoding]::new($false))

    $readback = [System.IO.File]::ReadAllText($resolvedConfig, $strictUtf8)
    foreach ($key in @($values.Keys)) {
        $keyPattern = '^[\t ]*{0}(?:(?:[\t ]*(?:=|:)[\t ]*)|[\t ]+)[^\r\n]*(?=\r?$)' -f
            [regex]::Escape($key)
        if ([regex]::Matches($readback, $keyPattern, $options).Count -ne 1) {
            throw "PLATFORM_SMOKE_VELOCITY_POLICY_READBACK_COUNT_INVALID: $key"
        }
        $exactPattern = '^{0}={1}(?=\r?$)' -f
            [regex]::Escape($key), [regex]::Escape([string]$values[$key])
        if ([regex]::Matches($readback, $exactPattern, $options).Count -ne 1) {
            throw "PLATFORM_SMOKE_VELOCITY_POLICY_READBACK_VALUE_INVALID: $key"
        }
    }
    return [ordered]@{
        velocity_policy_minecraft_versions = $MinecraftVersion
        velocity_policy_client_build_ids = $ClientBuildId
    }
}

function Test-SmokeRunLeaf([string]$Leaf) {
    return $Leaf -cmatch '^[0-9]{8}T[0-9]{9}Z-(?:1_21_11|26_1_2|26_2)-[0-9a-f]{32}$'
}

function Assert-SmokeRunLeaf([string]$Leaf) {
    if (-not (Test-SmokeRunLeaf $Leaf)) {
        throw 'PLATFORM_SMOKE_CSPRNG_RUN_LEAF_REQUIRED'
    }
}

function Initialize-SafeOwnedDirectory([string]$Path, [string]$ExpectedParent) {
    $parent = Assert-DirectLocalPath $ExpectedParent -Directory
    $full = [System.IO.Path]::GetFullPath($Path)
    if (-not [System.IO.Path]::GetDirectoryName($full).Equals(
            $parent, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PLATFORM_SMOKE_DIRECTORY_PARENT_INVALID'
    }
    if (-not (Test-Path -LiteralPath $full)) {
        $null = New-Item -ItemType Directory -Path $full -ErrorAction Stop
    }
    $resolved = Assert-DirectLocalPath $full -Directory
    if (-not [System.IO.Path]::GetDirectoryName($resolved).Equals(
            $parent, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PLATFORM_SMOKE_DIRECTORY_PARENT_CHANGED'
    }
    return $resolved
}

function New-ExclusiveOwnedDirectory([string]$Path, [string]$ExpectedParent) {
    $parent = Assert-DirectLocalPath $ExpectedParent -Directory
    $full = [System.IO.Path]::GetFullPath($Path)
    if (-not [System.IO.Path]::GetDirectoryName($full).Equals(
            $parent, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PLATFORM_SMOKE_EXCLUSIVE_DIRECTORY_PARENT_INVALID'
    }
    if (Test-Path -LiteralPath $full) {
        throw 'PLATFORM_SMOKE_EXCLUSIVE_DIRECTORY_ALREADY_EXISTS'
    }
    $null = New-Item -ItemType Directory -Path $full -ErrorAction Stop
    $resolved = Assert-DirectLocalPath $full -Directory
    # Runtime authority files (for example Paper's proxy-public-key.txt) are
    # validated by the Java preflight against the Windows DACL of their
    # containing directory.  A normal New-Item inherits the controller's
    # broad Users/Authenticated Users write ACEs, so a freshly-created
    # plugins\MCAce directory would fail closed even though the file bytes are
    # correct.  Make every exclusive run directory a non-inheriting
    # current-user+SYSTEM tree; both principals can still create/read the
    # server's generated files, while untrusted principals cannot write them.
    if ([System.IO.Path]::DirectorySeparatorChar -eq '\') {
        try {
            $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
            $directorySecurity = New-Object System.Security.AccessControl.DirectorySecurity
            $directorySecurity.SetAccessRuleProtection($true, $false)
            $directorySecurity.SetOwner($current)
            $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            foreach ($sid in @($current, $system)) {
                $directorySecurity.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $sid,
                    [System.Security.AccessControl.FileSystemRights]::FullControl,
                    $inheritance,
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow)))
            }
            Set-Acl -LiteralPath $resolved -AclObject $directorySecurity -ErrorAction Stop
            $readbackAcl = Get-Acl -LiteralPath $resolved -ErrorAction Stop
            if (-not $readbackAcl.AreAccessRulesProtected -or
                    @($readbackAcl.Access).Count -ne 2) {
                throw 'exclusive directory DACL readback was not protected current-user+SYSTEM'
            }
        } catch {
            throw "PLATFORM_SMOKE_EXCLUSIVE_DIRECTORY_ACL_HARDENING_FAILED: $($_.Exception.Message)"
        }
    }
    if (-not [System.IO.Path]::GetDirectoryName($resolved).Equals(
            $parent, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PLATFORM_SMOKE_EXCLUSIVE_DIRECTORY_PARENT_CHANGED'
    }
    return $resolved
}

function Assert-OwnedTreeNoReparse([string]$Root) {
    $resolvedRoot = Assert-DirectLocalPath $Root -Directory
    $prefix = $resolvedRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $pending = [System.Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($resolvedRoot)
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        foreach ($entry in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "PLATFORM_SMOKE_REPARSE_TREE_ENTRY_REJECTED: $($entry.Name)"
            }
            $resolvedEntry = [System.IO.Path]::GetFullPath($entry.FullName)
            if (-not $resolvedEntry.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'PLATFORM_SMOKE_TREE_ENTRY_ESCAPE_REJECTED'
            }
            if ($entry.PSIsContainer) {
                $pending.Enqueue((Assert-DirectLocalPath $resolvedEntry -Directory))
            } else {
                $null = Assert-DirectLocalPath $resolvedEntry
            }
        }
    }
    return $resolvedRoot
}

function Get-VerifiedArtifact([System.Collections.IDictionary]$Artifact) {
    $urlMatch = [regex]::Match($Artifact.Url, '^https://fill-data\.papermc\.io/v1/objects/(?<urlHash>[0-9a-f]{64})/[^/]+$')
    if ((-not $urlMatch.Success) -or ($Artifact.Sha256 -notmatch '^[0-9a-f]{64}$') -or
            ($urlMatch.Groups['urlHash'].Value -ne $Artifact.Sha256)) {
        throw "Artifact source or SHA-256 declaration is not a fixed official PaperMC value: $($Artifact.Name)"
    }
    $path = [string]$Artifact.Path
    if (-not (Test-Path -LiteralPath $path)) {
        throw "PLATFORM_SMOKE_PINNED_CACHE_REQUIRED: $($Artifact.Name)"
    }
    $resolved = Assert-DirectLocalPath $path
    if ($null -ne $Artifact.Size -and (Get-Item -LiteralPath $resolved).Length -ne [long]$Artifact.Size) {
        throw "Cached artifact failed size verification: $($Artifact.Name)"
    }
    if ((Get-Sha256 $resolved) -ne $Artifact.Sha256) {
        throw "Cached artifact failed SHA-256 verification: $($Artifact.Name)"
    }
    return $resolved
}

function Get-FreeLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

function Test-LoopbackPortFree([int]$Port) {
    return -not @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -eq $Port -and $_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::') }).Count
}

function Assert-LoopbackListener($Service, [int]$Port) {
    # Windows CIM can raise a terminating "no matching objects" error for a
    # freshly-bound port when the listener table has not caught up with the
    # server's readiness log.  Query the listen set with a non-terminating
    # error policy and briefly retry so the readiness check is race-tolerant,
    # while retaining the loopback-only and owning-process assertions below.
    $listeners = @()
    # A second launch in the same isolated runtime can spend tens of seconds
    # rebuilding plugin state before Netty binds, even after a readiness line
    # from the prior bootstrap phase is still present in the log directory.
    # Stay within the surrounding 150/300-second marker budgets while allowing
    # that real bind to appear instead of rejecting a stale-log race.
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while ([DateTime]::UtcNow -lt $deadline) {
        $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -eq $Port -and
                $_.LocalAddress -in @('127.0.0.1', '::1') })
        if ($listeners.Count -gt 0) { break }
        if ($Service.Process.HasExited) { break }
        Start-Sleep -Milliseconds 250
    }
    if ($listeners.Count -eq 0) {
        throw "$($Service.Name) did not expose the expected loopback listener on port $Port"
    }
    if (@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -eq $Port -and
                $_.LocalAddress -notin @('127.0.0.1', '::1') }).Count -ne 0) {
        throw "$($Service.Name) exposed a non-loopback listener on port $Port"
    }
    if (-not @($listeners | Where-Object { $_.OwningProcess -eq $Service.Pid }).Count) {
        throw "$($Service.Name) loopback listener on port $Port is not owned by its smoke process"
    }
    return [int]$listeners[0].OwningProcess
}

function Get-JavaVersionText([string]$Executable) {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    Set-ProcessArguments $startInfo @('-version')
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { return '' }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        return $stdout + $stderr
    } finally {
        $process.Dispose()
    }
}

function Set-ProcessArguments(
        [System.Diagnostics.ProcessStartInfo]$StartInfo,
        [string[]]$Arguments) {
    if ($null -ne $StartInfo.PSObject.Properties['ArgumentList']) {
        foreach ($argument in $Arguments) {
            [void]$StartInfo.ArgumentList.Add($argument)
        }
        return
    }

    # Windows PowerShell 5.1 runs on .NET Framework, whose ProcessStartInfo has
    # only the legacy Arguments string. Java/Gradle arguments used by this gate
    # never end in a path separator, so standard quoted Windows arguments are
    # sufficient while preserving paths that contain spaces.
    $StartInfo.Arguments = (@($Arguments | ForEach-Object {
        '"' + ([string]$_).Replace('"', '\"') + '"'
    }) -join ' ')
}

function Test-TextContains(
        [string]$Content,
        [string]$Needle,
        [StringComparison]$Comparison = [StringComparison]::Ordinal) {
    return $null -ne $Content -and $Content.IndexOf($Needle, $Comparison) -ge 0
}

function Normalize-FabricConsentEvidence([System.Collections.IDictionary]$Evidence) {
    # Schema-8 compatibility fields describe the one visible connection-enablement
    # screen.  They are aliases, not evidence that another explicit-file screen was
    # rendered later in the connection.
    $Evidence['explicit_file_requested'] = [bool]$Evidence['enablement_requested']
    $Evidence['explicit_file_rendered'] = [bool]$Evidence['enablement_rendered']
    $Evidence['explicit_file_accepted'] = [bool]$Evidence['enablement_accepted']

    # GAME_RENDER_FRAME inherits that accepted connection decision.  A producer
    # that observes both a separately rendered frame prompt and inheritance is
    # contradictory and must fail rather than publish two-human-confirmation data.
    if ([bool]$Evidence['game_render_frame_rendered'] -and
            [bool]$Evidence['game_render_frame_inherited']) {
        throw 'PLATFORM_SMOKE_GAME_RENDER_FRAME_RENDERED_AND_INHERITED'
    }
    if ([bool]$Evidence['game_render_frame_inherited']) {
        $Evidence['game_render_frame_rendered'] = $false
        $Evidence['game_render_frame_allowed'] = $true
    }
}

function Update-FabricConsentEvidence(
        [System.Collections.IDictionary]$Evidence,
        [string]$LogPath) {
    if ([string]::IsNullOrWhiteSpace($LogPath) -or -not (Test-Path -LiteralPath $LogPath)) {
        return
    }
    $content = Get-Content -Raw -LiteralPath $LogPath -ErrorAction SilentlyContinue
    $entryMarkers = [regex]::Matches(
        $content, 'MCAce explicit-file manifest prepared entries=(?<count>[0-9]+)')
    if ($entryMarkers.Count -gt 0) {
        $observedEntries = [int]$entryMarkers[$entryMarkers.Count - 1].Groups['count'].Value
        if ($observedEntries -gt [int]$Evidence['explicit_file_manifest_entries']) {
            $Evidence['explicit_file_manifest_entries'] = $observedEntries
        }
    }
    $markers = [ordered]@{
        enablement_requested = 'MCAce enablement consent requested for signed policy; explicit-file paths='
        enablement_rendered = 'MCAce enablement consent screen rendered'
        enablement_accepted = 'MCAce enablement accepted for the current connection'
        explicit_file_requested = 'MCAce explicit-file consent requested for '
        explicit_file_rendered = 'MCAce explicit-file consent screen rendered'
        explicit_file_accepted = 'MCAce explicit-file authorization accepted for the current connection'
        authenticated = 'MCAce session verified at trust level VERIFIED'
        game_render_frame_requested = 'MCAce evidence request accepted under connection enablement; no second consent screen'
        game_render_frame_rendered = 'MCAce evidence consent screen rendered for signed GAME_RENDER_FRAME request'
        game_render_frame_allowed = 'MCAce evidence consent allowed once for signed GAME_RENDER_FRAME request'
        game_render_frame_inherited = 'MCAce evidence consent inherited from connection enablement'
        game_render_frame_completed = 'MCAce evidence transfer COMPLETE request='
    }
    foreach ($entry in $markers.GetEnumerator()) {
        if (-not [bool]$Evidence[$entry.Key] -and (Test-TextContains $content $entry.Value)) {
            $Evidence[$entry.Key] = $true
        }
    }
    Normalize-FabricConsentEvidence $Evidence
}

function Get-FabricGuiStage(
        [System.Collections.IDictionary]$Evidence,
        [string]$Fallback) {
    if ([bool]$Evidence['game_render_frame_completed']) { return 'EVIDENCE_COMPLETE' }
    if ([bool]$Evidence['game_render_frame_inherited']) { return 'EVIDENCE_INHERITED' }
    if ([bool]$Evidence['game_render_frame_requested']) { return 'EVIDENCE_REQUESTED' }
    if ([bool]$Evidence['authenticated']) { return 'AUTHENTICATED' }
    if ([bool]$Evidence['enablement_accepted']) { return 'ENABLEMENT_ACCEPTED' }
    if ([bool]$Evidence['enablement_rendered']) { return 'ENABLEMENT_RENDERED' }
    if ([bool]$Evidence['enablement_requested']) { return 'ENABLEMENT_REQUESTED' }
    return $Fallback
}

function Test-FabricGuiCoverage([System.Collections.IDictionary]$Evidence) {
    Normalize-FabricConsentEvidence $Evidence
    return [bool]$Evidence['enablement_requested'] -and
        [bool]$Evidence['enablement_rendered'] -and
        [bool]$Evidence['enablement_accepted'] -and
        [bool]$Evidence['explicit_file_requested'] -and
        [bool]$Evidence['explicit_file_rendered'] -and
        [bool]$Evidence['explicit_file_accepted'] -and
        [int]$Evidence['explicit_file_manifest_entries'] -eq 1 -and
        [bool]$Evidence['authenticated']
}

function Test-FabricEvidenceCoverage([System.Collections.IDictionary]$Evidence) {
    Normalize-FabricConsentEvidence $Evidence
    return (Test-FabricGuiCoverage $Evidence) -and
        [bool]$Evidence['game_render_frame_requested'] -and
        -not [bool]$Evidence['game_render_frame_rendered'] -and
        [bool]$Evidence['game_render_frame_allowed'] -and
        [bool]$Evidence['game_render_frame_inherited'] -and
        [bool]$Evidence['game_render_frame_completed']
}

function New-SanitizedReleaseReport(
        [System.Collections.IDictionary]$ConsentEvidence,
        [bool]$FabricClientRequested,
        [bool]$FabricEvidenceRequested,
        [bool]$FabricRuntimeJarLoaded,
        [bool]$FabricReleaseJarLoaded,
        [bool]$ExplicitFileFixturePresent,
        [bool]$EvidenceAuditSummaryObserved,
        [bool]$PersistentIdentityUnchanged,
        [bool]$VelocityTransportClassesPresent,
        [bool]$PaperAdmissionChannelEnabled,
        [bool]$NegativePinFailureObserved,
        [bool]$NegativePluginDisabled,
        [bool]$NegativeChannelMarkerAbsent,
        [bool]$DiagnosticsRetained,
        [int]$AssertionCount,
        [int]$RemainingOwnedProcessCount,
        [System.Collections.IDictionary]$VelocityPolicyTuple) {
    Normalize-FabricConsentEvidence $ConsentEvidence
    return [ordered]@{
        schema = $reportSchema
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        artifact_class = $fabricArtifactClass
        status = 'passed'
        release_evidence = $false
        diagnostics_retained = $DiagnosticsRetained
        fabric_target = $FabricTarget
        minecraft_version = [string]$fabricDescriptor.minecraft_version
        velocity_policy_minecraft_versions = [string]$VelocityPolicyTuple['velocity_policy_minecraft_versions']
        velocity_policy_client_build_ids = [string]$VelocityPolicyTuple['velocity_policy_client_build_ids']
        fabric_api_version = [string]$fabricDescriptor.fabric_api_version
        fabric_artifact_kind = [string]$fabricDescriptor.artifact_kind
        fabric_java_major = [int]$fabricDescriptor.java_major
        fabric_runtime_mode = $fabricRuntimeMode
        fabric_runtime_jar_loaded = $FabricRuntimeJarLoaded
        fabric_release_jar_loaded = $FabricReleaseJarLoaded
        fabric_client_requested = $FabricClientRequested
        fabric_evidence_requested = $FabricEvidenceRequested
        enablement_consent_requested = [bool]$ConsentEvidence['enablement_requested']
        enablement_consent_rendered = [bool]$ConsentEvidence['enablement_rendered']
        enablement_consent_accepted = [bool]$ConsentEvidence['enablement_accepted']
        explicit_file_fixture_present = $ExplicitFileFixturePresent
        explicit_file_manifest_entries = [int]$ConsentEvidence['explicit_file_manifest_entries']
        explicit_file_manifest_entries_observed = ([int]$ConsentEvidence['explicit_file_manifest_entries'] -eq 1)
        explicit_file_consent_requested = [bool]$ConsentEvidence['explicit_file_requested']
        explicit_file_consent_rendered = [bool]$ConsentEvidence['explicit_file_rendered']
        explicit_file_consent_accepted = [bool]$ConsentEvidence['explicit_file_accepted']
        fabric_authenticated = [bool]$ConsentEvidence['authenticated']
        game_render_frame_requested = [bool]$ConsentEvidence['game_render_frame_requested']
        game_render_frame_consent_rendered = [bool]$ConsentEvidence['game_render_frame_rendered']
        game_render_frame_consent_allowed = [bool]$ConsentEvidence['game_render_frame_allowed']
        game_render_frame_consent_inherited = [bool]$ConsentEvidence['game_render_frame_inherited']
        game_render_frame_completed = [bool]$ConsentEvidence['game_render_frame_completed']
        fabric_gui_coverage = ($FabricClientRequested -and (Test-FabricGuiCoverage $ConsentEvidence))
        fabric_evidence_coverage = ($FabricEvidenceRequested -and (Test-FabricEvidenceCoverage $ConsentEvidence))
        raw_evidence_retained = $false
        evidence_audit_summary_observed = $EvidenceAuditSummaryObserved
        persistent_identity_unchanged = $PersistentIdentityUnchanged
        velocity_transport_classes_present = $VelocityTransportClassesPresent
        paper_admission_channel_enabled = $PaperAdmissionChannelEnabled
        paper_missing_pin_failure_observed = $NegativePinFailureObserved
        paper_missing_pin_plugin_disabled = $NegativePluginDisabled
        paper_missing_pin_channel_absent = $NegativeChannelMarkerAbsent
        loopback_listener_count = 2
        assertion_count = $AssertionCount
        cleanup_completed = $false
        cleanup_ports_free = $false
        remaining_owned_process_count = $RemainingOwnedProcessCount
    }
}

function Write-DiagnosticsNotice([string]$RunDirectory, [string]$Reason) {
    $notice = @(
        'MCAce platform smoke diagnostics - NOT RELEASE EVIDENCE',
        $Reason,
        'These files can contain raw logs, local paths, player identifiers, request identifiers, hashes, and operator-provided values.',
        'A passing report proves final Fabric artifact GUI loading, but remains manual GUI evidence rather than complete release evidence.'
    ) -join [Environment]::NewLine
    [System.IO.File]::WriteAllText(
        (Join-Path $RunDirectory 'DIAGNOSTICS-NON-RELEASE.txt'),
        $notice,
        [System.Text.UTF8Encoding]::new($false))
}

function Remove-UnretainedDiagnostics(
        [string]$RunDirectory,
        [string]$ReportFile,
        [string]$BindingFile = '') {
    $allowedRoot = Assert-DirectLocalPath $runsRoot -Directory
    $resolvedRun = Assert-OwnedTreeNoReparse $RunDirectory
    Assert-SmokeRunLeaf ([System.IO.Path]::GetFileName($resolvedRun))
    if (-not [System.IO.Path]::GetDirectoryName($resolvedRun).Equals(
            $allowedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to remove diagnostics outside the platform-smoke runs directory'
    }
    $resolvedReport = [System.IO.Path]::GetFullPath($ReportFile)
    $reportDirectory = [System.IO.Path]::GetDirectoryName($resolvedReport).TrimEnd('\', '/')
    if (-not $reportDirectory.Equals($resolvedRun, [StringComparison]::OrdinalIgnoreCase) -or
            -not [System.IO.Path]::GetFileName($resolvedReport).Equals(
                'report.json', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to remove diagnostics without the run-local report.json boundary'
    }
    $retained = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [void]$retained.Add($resolvedReport)
    if (-not [string]::IsNullOrWhiteSpace($BindingFile)) {
        $resolvedBinding = [System.IO.Path]::GetFullPath($BindingFile)
        $bindingDirectory = [System.IO.Path]::GetDirectoryName($resolvedBinding).TrimEnd('\', '/')
        if (-not $bindingDirectory.Equals($resolvedRun, [StringComparison]::OrdinalIgnoreCase) -or
                -not [System.IO.Path]::GetFileName($resolvedBinding).Equals(
                    'binding.json', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to retain a binding outside the run-local binding.json boundary'
        }
        [void]$retained.Add($resolvedBinding)
    }
    foreach ($entry in @(Get-ChildItem -Force -LiteralPath $resolvedRun)) {
        $resolvedEntry = [System.IO.Path]::GetFullPath($entry.FullName)
        if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not [System.IO.Path]::GetDirectoryName($resolvedEntry).Equals(
                    $resolvedRun, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove a non-owned diagnostic entry'
        }
        if (-not $retained.Contains($resolvedEntry)) {
            Remove-Item -LiteralPath $resolvedEntry -Recurse -Force
        }
    }
}

function Get-Sha256HexFromBytes([byte[]]$Bytes) {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Get-CompatibleRelativePath([string]$BaseDirectory, [string]$Path) {
    $relativePathMethod = [System.IO.Path].GetMethods() |
        Where-Object { $_.Name -eq 'GetRelativePath' -and $_.GetParameters().Count -eq 2 } |
        Select-Object -First 1
    if ($null -ne $relativePathMethod) {
        return [System.IO.Path]::GetRelativePath($BaseDirectory, $Path)
    }
    $basePath = [System.IO.Path]::GetFullPath($BaseDirectory).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $targetPath = [System.IO.Path]::GetFullPath($Path)
    $relativeUri = ([Uri]$basePath).MakeRelativeUri([Uri]$targetPath)
    return [Uri]::UnescapeDataString($relativeUri.ToString()).Replace('/', [System.IO.Path]::DirectorySeparatorChar)
}

function Resolve-ExactJava([int]$Major, [string]$ConfiguredHome, [string]$Role) {
    if ([string]::IsNullOrWhiteSpace($ConfiguredHome)) {
        throw "PLATFORM_SMOKE_${Role}_JAVA_HOME_${Major}_REQUIRED"
    }
    $java = Assert-DirectLocalPath (Join-Path $ConfiguredHome 'bin\java.exe')
    $version = [string](Get-Item -LiteralPath $java).VersionInfo.FileVersion
    if ($version -notmatch ('^{0}(?:\.|$)' -f $Major)) {
        throw "PLATFORM_SMOKE_EXACT_${Role}_JAVA_${Major}_REQUIRED"
    }
    return [pscustomobject]@{
        path = $java
        sha256 = Get-Sha256 $java
        file_version = $version
    }
}

function Resolve-RootJava21 {
    $javaHome = if (-not [string]::IsNullOrWhiteSpace($env:MCACE_JAVA21_HOME)) {
        $env:MCACE_JAVA21_HOME
    } else { $env:JAVA_HOME }
    return Resolve-ExactJava 21 $javaHome 'ROOT'
}

function Resolve-TargetJava {
    $major = [int]$fabricDescriptor.java_major
    if ($major -eq 21) { return Resolve-RootJava21 }
    return Resolve-ExactJava 25 $env:MCACE_JAVA25_HOME 'TARGET'
}

function Resolve-OfflineGradle961 {
    $gradleUserRoot = if (-not [string]::IsNullOrWhiteSpace($env:GRADLE_USER_HOME)) {
        $env:GRADLE_USER_HOME
    } elseif (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        Join-Path $env:USERPROFILE '.gradle'
    } else {
        throw 'PLATFORM_SMOKE_GRADLE_USER_HOME_REQUIRED'
    }
    $distributionRoot = Join-Path $gradleUserRoot 'wrapper\dists\gradle-9.6.1-bin'
    $launchers = @(Get-ChildItem -LiteralPath $distributionRoot -Recurse -File `
        -Filter 'gradle-launcher-9.6.1.jar' -ErrorAction Stop)
    if ($launchers.Count -ne 1) { throw 'PLATFORM_SMOKE_OFFLINE_GRADLE_9_6_1_REQUIRED' }
    $launcher = Assert-DirectLocalPath $launchers[0].FullName
    $libRoot = Split-Path -Parent $launcher
    $core = Assert-DirectLocalPath (Join-Path $libRoot 'gradle-core-9.6.1.jar')
    $gradleHome = Assert-DirectLocalPath (Split-Path -Parent $libRoot) -Directory
    if (-not [System.IO.Path]::GetFileName($gradleHome).Equals(
            'gradle-9.6.1', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PLATFORM_SMOKE_OFFLINE_GRADLE_9_6_1_LAYOUT_INVALID'
    }
    return [pscustomobject]@{
        version = $gradleVersion
        home = $gradleHome
        launcher = $launcher
        launcher_sha256 = Get-Sha256 $launcher
        core_sha256 = Get-Sha256 $core
    }
}

function Invoke-PinnedOfflineGradle(
        [string]$JavaPath,
        [string]$ProjectDirectory,
        [string[]]$Tasks,
        [string[]]$Properties,
        [bool]$RerunTasks,
        [string]$FailureCode) {
    $null = Assert-DirectLocalPath $JavaPath
    $null = Assert-DirectLocalPath $ProjectDirectory -Directory
    $arguments = [System.Collections.Generic.List[string]]::new()
    foreach ($argument in @(
            $runTokenJvmArgument,
            '-classpath',
            $script:OfflineGradle.launcher,
            'org.gradle.launcher.GradleMain',
            '--project-dir',
            $ProjectDirectory)) {
        $arguments.Add([string]$argument)
    }
    foreach ($task in $Tasks) { $arguments.Add([string]$task) }
    foreach ($property in $Properties) { $arguments.Add([string]$property) }
    if ($RerunTasks) { $arguments.Add('--rerun-tasks') }
    foreach ($argument in @('--offline', '--dependency-verification=strict',
            '--no-build-cache', '--no-configuration-cache', '--no-daemon', '--no-parallel',
            '--max-workers=1')) {
        $arguments.Add($argument)
    }
    $nativeArguments = $arguments.ToArray()
    & $JavaPath @nativeArguments
    if ($LASTEXITCODE -ne 0) { throw $FailureCode }
}

function Expand-VelocityConfiguration([string]$Jar, [string]$Destination, [int]$ProxyPort, [int]$PaperPort) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Jar)
    try {
        $entry = $archive.GetEntry('default-velocity.toml')
        if ($null -eq $entry) {
            throw 'Velocity artifact does not contain default-velocity.toml'
        }
        $reader = [System.IO.StreamReader]::new($entry.Open(), [System.Text.Encoding]::UTF8)
        try {
            $configuration = $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
    } finally {
        $archive.Dispose()
    }
    $configuration = $configuration.Replace('bind = "0.0.0.0:25565"', "bind = `"127.0.0.1:$ProxyPort`"")
    $configuration = $configuration.Replace('online-mode = true', 'online-mode = false')
    $configuration = $configuration.Replace('force-key-authentication = true', 'force-key-authentication = false')
    $configuration = $configuration.Replace('lobby = "127.0.0.1:30066"', "lobby = `"127.0.0.1:$PaperPort`"")
    [System.IO.File]::WriteAllText($Destination, $configuration, [System.Text.UTF8Encoding]::new($false))
}

function Test-JarEntry([string]$Jar, [string]$EntryName) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Jar)
    try { return $null -ne $archive.GetEntry($EntryName) }
    finally { $archive.Dispose() }
}

function Get-FabricArtifactIdentity([string]$Jar, [System.Collections.IDictionary]$Descriptor) {
    $resolved = Assert-DirectLocalPath $Jar
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($resolved)
    try {
        $entry = $archive.GetEntry('fabric.mod.json')
        if ($null -eq $entry) { throw 'PLATFORM_SMOKE_FABRIC_METADATA_REQUIRED' }
        $reader = [System.IO.StreamReader]::new($entry.Open(), [System.Text.Encoding]::UTF8)
        try { $raw = $reader.ReadToEnd() }
        finally { $reader.Dispose() }
    } finally {
        $archive.Dispose()
    }
    try { $metadata = $raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'PLATFORM_SMOKE_FABRIC_METADATA_INVALID' }
    $version = [string]$metadata.version
    $buildId = if ($null -ne $metadata.custom) {
        [string]$metadata.custom.'mcace:client_build_id'
    } else { '' }
    $minecraftDependency = if ($null -ne $metadata.depends) {
        [string]$metadata.depends.minecraft
    } else { '' }
    $fabricApiDependency = if ($null -ne $metadata.depends) {
        [string]$metadata.depends.'fabric-api'
    } else { '' }
    $javaDependency = if ($null -ne $metadata.depends) {
        [string]$metadata.depends.java
    } else { '' }
    if ($version -cne $fabricArtifactVersion -or
            $buildId -cnotmatch '^platform-smoke-[0-9]{8}T[0-9]{9}Z$' -or
            $minecraftDependency -cne [string]$Descriptor.minecraft_version -or
            $fabricApiDependency -cne [string]$Descriptor.fabric_api_version -or
            $javaDependency -cne ('>={0}' -f [int]$Descriptor.java_major)) {
        throw 'PLATFORM_SMOKE_FINAL_FABRIC_BUILD_IDENTITY_INVALID'
    }
    return [pscustomobject]@{
        version = $version
        build_id = $buildId
        minecraft_version = $minecraftDependency
        fabric_api_version = $fabricApiDependency
        java_major = [int]$Descriptor.java_major
        marker = "MCACE_FABRIC_ARTIFACT_LOADED version=$version build_id=$buildId"
    }
}

function Assert-FabricArtifactMarker([string]$LogPath, [string]$ExpectedMarker) {
    $prefix = 'MCACE_FABRIC_ARTIFACT_LOADED '
    $observed = [System.Collections.Generic.List[string]]::new()
    foreach ($line in @(Get-Content -LiteralPath $LogPath -ErrorAction Stop)) {
        $index = $line.IndexOf($prefix, [StringComparison]::Ordinal)
        if ($index -ge 0) {
            $observed.Add($line.Substring($index).TrimEnd())
        }
    }
    if ($observed.Count -ne 1 -or $observed[0] -cne $ExpectedMarker) {
        throw 'PLATFORM_SMOKE_EXACT_FABRIC_ARTIFACT_MARKER_REQUIRED'
    }
}

function Start-JavaService(
        [string]$Name,
        [string]$WorkingDirectory,
        [string]$Jar,
        [string]$MaximumHeap,
        [string[]]$ExtraArguments) {
    $java = $script:TargetJavaPath
    Assert-SmokeRunToken $runToken
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $java
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    Set-ProcessArguments $startInfo `
        (@($runTokenJvmArgument, '-Xms128m', "-Xmx$MaximumHeap", '-jar', $Jar) + $ExtraArguments)
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Could not start $Name"
    }
    return [pscustomobject]@{
        Name = $Name
        Process = $process
        Pid = $process.Id
        WorkingDirectory = $WorkingDirectory
        RunToken = $runToken
        Stdout = $process.StandardOutput.ReadToEndAsync()
        Stderr = $process.StandardError.ReadToEndAsync()
        ConsolePath = Join-Path $WorkingDirectory "$Name-console.log"
    }
}

function Start-FabricClient(
        [string]$RunDirectory,
        [string]$ServerAddress,
        [bool]$AwaitEvidence,
        [string]$ExpectedArtifactSha256) {
    if ($ExpectedArtifactSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'PLATFORM_SMOKE_EXPECTED_FABRIC_CODESOURCE_SHA256_REQUIRED'
    }
    Assert-SmokeRunToken $runToken
    $java = $script:TargetJavaPath
    $fabricProjectDirectory = [string]$fabricDescriptor.project_directory
    $loomRunDirectory = Get-CompatibleRelativePath $fabricProjectDirectory $RunDirectory
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $java
    $startInfo.WorkingDirectory = [string]$fabricDescriptor.gradle_project_directory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $arguments = [System.Collections.Generic.List[string]]::new()
    foreach ($argument in @(
            $runTokenJvmArgument,
            '-Xms128m',
            '-Xmx1024m',
            '-classpath',
            $script:OfflineGradle.launcher,
            'org.gradle.launcher.GradleMain',
            [string]$fabricDescriptor.run_task,
            "-PmcaceSmokeRunDirectory=$loomRunDirectory",
            "-PmcaceSmokeServerAddress=$ServerAddress",
            '-PmcaceSmokeArtifactMode=true',
            "-PmcaceSmokeConsentTimeoutSeconds=$manualConsentHandshakeTimeoutSeconds",
            "-PmcaceClientBuildId=$fabricSmokeBuildId",
            "-PmcaceSmokeExpectedArtifactSha256=$ExpectedArtifactSha256",
            "-PmcaceSmokeRunToken=$runToken",
            '--rerun-tasks',
            '--offline',
            '--dependency-verification=strict',
            '--no-build-cache',
            '--no-configuration-cache',
            '--no-daemon',
            '--no-parallel',
            '--max-workers=1')) {
        $arguments.Add($argument)
    }
    if ([int]$fabricDescriptor.java_major -eq 25) {
        $arguments.Insert(7, "-PmcaceRootDepsDir=$stagedModernDependencies")
        $arguments.Insert(8, "-PmcaceProductVersion=$fabricArtifactVersion")
    }
    if ($AwaitEvidence) {
        $arguments.Add('-PmcaceSmokeEvidence=true')
    }
    Set-ProcessArguments $startInfo $arguments.ToArray()
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'Could not start the Fabric final artifact client'
    }
    return [pscustomobject]@{
        Name = 'fabric-client'
        Process = $process
        Pid = $process.Id
        WorkingDirectory = $RunDirectory
        RunToken = $runToken
        Stdout = $process.StandardOutput.ReadToEndAsync()
        Stderr = $process.StandardError.ReadToEndAsync()
        ConsolePath = Join-Path $RunDirectory 'fabric-client-console.log'
    }
}

function Get-SmokeProcessTreeTargets(
        [object[]]$Snapshot,
        [int]$RootPid,
        [string]$RunToken) {
    Assert-SmokeRunToken $RunToken
    $pending = [System.Collections.Generic.Queue[int]]::new()
    $pending.Enqueue($RootPid)
    $visited = [System.Collections.Generic.HashSet[int]]::new()
    [void]$visited.Add($RootPid)
    $targets = [System.Collections.Generic.List[int]]::new()
    while ($pending.Count -gt 0) {
        $parentPid = $pending.Dequeue()
        foreach ($child in $Snapshot | Where-Object { $_.ParentProcessId -eq $parentPid }) {
            $childPid = [int]$child.ProcessId
            if ($visited.Add($childPid)) {
                $pending.Enqueue($childPid)
                if ($child.Name -in @('java.exe', 'javaw.exe') -and
                        -not [string]::IsNullOrEmpty([string]$child.CommandLine) -and
                        (Test-ExactRunTokenArgument ([string]$child.CommandLine) $RunToken)) {
                    $targets.Add($childPid)
                }
            }
        }
    }
    $result = $targets.ToArray()
    [Array]::Reverse($result)
    return $result
}

function Stop-SmokeProcessTree([int]$RootPid, [string]$RunToken) {
    $snapshot = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    foreach ($targetPid in @(Get-SmokeProcessTreeTargets $snapshot $RootPid $RunToken)) {
        Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
    }
}

function Get-RunTokenJavaProcesses([string]$RunToken) {
    Assert-SmokeRunToken $RunToken
    return @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $_.Name -in @('java.exe', 'javaw.exe') -and
        -not [string]::IsNullOrWhiteSpace([string]$_.CommandLine) -and
        (Test-ExactRunTokenArgument ([string]$_.CommandLine) $RunToken)
    })
}

function Stop-RunTokenJavaProcesses([string]$RunToken) {
    Assert-SmokeRunToken $RunToken
    foreach ($candidate in @(Get-RunTokenJavaProcesses $RunToken)) {
        $candidatePid = [int]$candidate.ProcessId
        $current = @(Get-CimInstance Win32_Process -Filter "ProcessId = $candidatePid" -ErrorAction Stop)
        if ($current.Count -ne 1 -or $current[0].Name -notin @('java.exe', 'javaw.exe') -or
                [string]::IsNullOrWhiteSpace([string]$current[0].CommandLine) -or
                -not (Test-ExactRunTokenArgument ([string]$current[0].CommandLine) $RunToken)) {
            continue
        }
        Stop-Process -Id $candidatePid -Force -ErrorAction Stop
    }
}

function Stop-JavaService($Service, [string]$Command) {
    if ($null -eq $Service) {
        return
    }
    $process = $Service.Process
    $rootPid = $Service.Pid
    if (-not $process.HasExited) {
        if (-not [string]::IsNullOrEmpty($Command)) {
            try {
                $process.StandardInput.WriteLine($Command)
                $process.StandardInput.Flush()
            } catch {
                Write-Warning "Could not send graceful shutdown to $($Service.Name): $($_.Exception.Message)"
            }
        }
        if (-not $process.WaitForExit(30000)) {
            # Enumerate the live tree before stopping the exact root: a terminated parent can
            # re-parent descendants. Only Java descendants carrying this run's exact random-token
            # JVM argument are eligible; unrelated Java processes are never selected.
            try {
                Stop-SmokeProcessTree $rootPid $Service.RunToken
            } catch {
                Write-Warning "Could not enumerate marker-bound descendants for $($Service.Name): $($_.Exception.Message)"
            }
            if (-not $process.HasExited) {
                # Parameterless Kill exists on both Windows PowerShell 5.1/.NET Framework and
                # PowerShell 7. The Process object is the exact root started by this smoke.
                $process.Kill()
                [void]$process.WaitForExit(10000)
            }
            Write-Warning "Forcibly stopped $($Service.Name) after graceful shutdown timeout"
        }
    }
    Stop-SmokeProcessTree $rootPid $Service.RunToken
    $stdout = if ($null -eq $Service.Stdout) { '' } else { $Service.Stdout.GetAwaiter().GetResult() }
    $stderr = if ($null -eq $Service.Stderr) { '' } else { $Service.Stderr.GetAwaiter().GetResult() }
    [System.IO.File]::WriteAllText(
        $Service.ConsolePath,
        $stdout + [Environment]::NewLine + $stderr,
        [System.Text.UTF8Encoding]::new($false))
    $process.Dispose()
}

function Wait-ServiceLog($Service, [string]$LogPath, [string[]]$RequiredText, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $LogPath) {
            $content = Get-Content -Raw -LiteralPath $LogPath -ErrorAction SilentlyContinue
            if ($null -eq $content) {
                $content = ''
            }
            $allPresent = $true
            foreach ($text in $RequiredText) {
                if (-not (Test-TextContains $content $text)) {
                    $allPresent = $false
                    break
                }
            }
            if ($allPresent) {
                return
            }
        }
        if ($Service.Process.HasExited) {
            throw "$($Service.Name) exited before its readiness markers were observed"
        }
        Start-Sleep -Seconds 1
    }
    throw "$($Service.Name) did not emit all readiness markers within $TimeoutSeconds seconds"
}

function Get-FabricDevelopmentPlayerName([string]$LogPath) {
    $line = Get-Content -LiteralPath $LogPath -ErrorAction Stop |
        Where-Object { $_ -match 'Setting user: (?<name>[A-Za-z0-9_]{3,16})$' } |
        Select-Object -Last 1
    if ($null -eq $line -or $line -notmatch 'Setting user: (?<name>[A-Za-z0-9_]{3,16})$') {
        throw 'Fabric development profile name was not observed in the local client log'
    }
    return $Matches['name']
}

function Get-BytesSha256([byte[]]$Bytes) {
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
}

function Get-ManifestSha256([string[]]$Entries) {
    $raw = (@($Entries | Sort-Object) -join "`n")
    return Get-BytesSha256 ([System.Text.UTF8Encoding]::new($false).GetBytes($raw))
}

function Get-SourceManifestBinding {
    $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    foreach ($relative in @('build.gradle.kts', 'settings.gradle.kts', 'gradle.properties',
            'gradlew', 'gradlew.bat')) {
        $files.Add((Get-Item -LiteralPath (Join-Path $repoRoot $relative) -Force -ErrorAction Stop))
    }
    foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $repoRoot 'gradle') `
            -Recurse -Force -File -ErrorAction Stop)) {
        $files.Add($file)
    }
    foreach ($module in @(Get-ChildItem -LiteralPath $repoRoot -Directory -Filter 'mcace-*' -Force)) {
        foreach ($name in @('build.gradle.kts', 'gradle.lockfile')) {
            $candidate = Join-Path $module.FullName $name
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                $files.Add((Get-Item -LiteralPath $candidate -Force))
            }
        }
        $sourceRoot = Join-Path $module.FullName 'src'
        if (Test-Path -LiteralPath $sourceRoot -PathType Container) {
            foreach ($file in @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -Force -File)) {
                $files.Add($file)
            }
        }
    }
    $modernRoot = Join-Path $repoRoot 'fabric-modern'
    foreach ($relative in @(
            'build.gradle.kts',
            'settings.gradle.kts',
            'gradle.properties',
            'gradle\verification-metadata.xml',
            'client-26.1.2\gradle.lockfile',
            'client-26.2\gradle.lockfile')) {
        $candidate = Join-Path $modernRoot $relative
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "PLATFORM_SMOKE_MODERN_SOURCE_INPUT_REQUIRED: $relative"
        }
        $files.Add((Get-Item -LiteralPath $candidate -Force))
    }
    $modernSourceRoot = Join-Path $modernRoot 'src'
    foreach ($file in @(Get-ChildItem -LiteralPath $modernSourceRoot -Recurse -Force -File)) {
        $files.Add($file)
    }
    $entries = foreach ($file in @($files | Sort-Object FullName -Unique)) {
        $resolved = Assert-DirectLocalPath $file.FullName
        $relative = $resolved.Substring($repoRoot.Length + 1).Replace('\', '/')
        "$relative|$($file.Length)|$(Get-Sha256 $resolved)"
    }
    return [pscustomobject]@{
        sha256 = Get-ManifestSha256 $entries
        file_count = [int]@($entries).Count
    }
}

function Assert-CanonicalPreparedRelative([string]$Relative) {
    if ([string]::IsNullOrWhiteSpace($Relative) -or $Relative.Contains('\') -or
            $Relative.StartsWith('/') -or $Relative.Contains(':')) {
        throw "PLATFORM_SMOKE_PREPARED_RELATIVE_INVALID: $Relative"
    }
    $segments = @($Relative.Split('/'))
    if ($segments.Count -lt 2 -or $segments[0] -notin @('cache', 'libraries', 'versions') -or
            @($segments | Where-Object { $_ -in @('', '.', '..') }).Count -ne 0) {
        throw "PLATFORM_SMOKE_PREPARED_RELATIVE_INVALID: $Relative"
    }
}

function Get-PreparedTreeBinding([string]$Root) {
    $resolved = Assert-DirectLocalPath $Root -Directory
    $entries = [System.Collections.Generic.List[string]]::new()
    $totalSize = 0L
    foreach ($directoryName in @('cache', 'libraries', 'versions')) {
        $directory = Assert-DirectLocalPath (Join-Path $resolved $directoryName) -Directory
        $null = Assert-OwnedTreeNoReparse $directory
        foreach ($file in @(Get-ChildItem -LiteralPath $directory -Recurse -Force -File)) {
            $bound = Assert-DirectLocalPath $file.FullName
            $relative = $bound.Substring($resolved.Length + 1).Replace('\', '/')
            Assert-CanonicalPreparedRelative $relative
            $sha256 = Get-Sha256 $bound
            $entries.Add("$relative|$($file.Length)|$sha256")
            $totalSize += [long]$file.Length
        }
    }
    if ($entries.Count -eq 0) { throw 'PLATFORM_SMOKE_PREPARED_PAPER_CACHE_REQUIRED' }
    return [pscustomobject]@{
        sha256 = Get-ManifestSha256 $entries.ToArray()
        file_count = [int]$entries.Count
        total_size = $totalSize
    }
}

function Get-PreparedPaperBinding {
    $manifestPath = Assert-DirectLocalPath $serverPreparedManifest
    try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'PLATFORM_SMOKE_PREPARED_MANIFEST_JSON_INVALID' }
    if (-not (Test-ExactJsonProperties $manifest @('schema', 'generated_at', 'roots', 'trees')) -or
            $manifest.schema -cne 'MCACE_SERVER_VERSION_MATRIX_PREPARED_V1' -or
            [string]::IsNullOrWhiteSpace([string]$manifest.generated_at) -or
            ((@($manifest.roots) -join ',') -cne 'cache,libraries,versions') -or
            @($manifest.trees).Count -ne 6) {
        throw 'PLATFORM_SMOKE_PREPARED_MANIFEST_SCHEMA_INVALID'
    }
    $generatedAt = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse(
            [string]$manifest.generated_at,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$generatedAt)) {
        throw 'PLATFORM_SMOKE_PREPARED_MANIFEST_TIMESTAMP_INVALID'
    }

    $assetManifestPath = Assert-DirectLocalPath $serverMatrixManifest
    try { $assetManifest = Get-Content -LiteralPath $assetManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'PLATFORM_SMOKE_SERVER_MATRIX_MANIFEST_INVALID' }
    $sourceAssets = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($asset in @($assetManifest.assets | Where-Object { $_.project -in @('paper', 'folia') })) {
        $identity = '{0}:{1}:{2}' -f [string]$asset.project, [string]$asset.version, [string]$asset.build
        if ($sourceAssets.ContainsKey($identity)) {
            throw 'PLATFORM_SMOKE_PREPARED_SOURCE_ASSET_DUPLICATE'
        }
        $sourceAssets.Add($identity, $asset)
    }
    if ($sourceAssets.Count -ne 6) { throw 'PLATFORM_SMOKE_PREPARED_SOURCE_ASSET_SET_INVALID' }

    $seenTrees = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $selectedTree = $null
    foreach ($tree in @($manifest.trees)) {
        if (-not (Test-ExactJsonProperties $tree @('project', 'version', 'build', 'server_sha256', 'files')) -or
                [string]$tree.project -notin @('paper', 'folia') -or
                [string]$tree.server_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                @($tree.files).Count -eq 0) {
            throw 'PLATFORM_SMOKE_PREPARED_MANIFEST_TREE_INVALID'
        }
        $identity = '{0}:{1}:{2}' -f [string]$tree.project, [string]$tree.version, [string]$tree.build
        if (-not $seenTrees.Add($identity) -or -not $sourceAssets.ContainsKey($identity)) {
            throw "PLATFORM_SMOKE_PREPARED_MANIFEST_TREE_IDENTITY_INVALID: $identity"
        }
        $sourceAsset = $sourceAssets[$identity]
        if ([string]$tree.server_sha256 -cne [string]$sourceAsset.sha256) {
            throw "PLATFORM_SMOKE_PREPARED_MANIFEST_SERVER_MISMATCH: $identity"
        }
        $seenFiles = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($file in @($tree.files)) {
            if (-not (Test-ExactJsonProperties $file @('relative', 'size', 'sha256')) -or
                    [string]$file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                    -not (Test-JsonInteger $file.size) -or [long]$file.size -lt 0L) {
                throw "PLATFORM_SMOKE_PREPARED_MANIFEST_FILE_INVALID: $identity"
            }
            $relative = [string]$file.relative
            Assert-CanonicalPreparedRelative $relative
            if (-not $seenFiles.Add($relative)) {
                throw "PLATFORM_SMOKE_PREPARED_MANIFEST_FILE_DUPLICATE: $identity"
            }
        }
        if ([string]$tree.project -ceq 'paper' -and
                [string]$tree.version -ceq $FabricTarget -and
                [string]$tree.build -ceq [string]$fabricDescriptor.paper_build) {
            if ($null -ne $selectedTree) { throw 'PLATFORM_SMOKE_PREPARED_TARGET_DUPLICATE' }
            $selectedTree = $tree
        }
    }
    if ($seenTrees.Count -ne $sourceAssets.Count -or $null -eq $selectedTree) {
        throw 'PLATFORM_SMOKE_PREPARED_TARGET_TREE_REQUIRED'
    }

    $expectedEntries = [System.Collections.Generic.List[string]]::new()
    $expectedTotalSize = 0L
    foreach ($file in @($selectedTree.files)) {
        $expectedEntries.Add("$($file.relative)|$([long]$file.size)|$($file.sha256)")
        $expectedTotalSize += [long]$file.size
    }
    $expectedTreeSha256 = Get-ManifestSha256 $expectedEntries.ToArray()
    $actual = Get-PreparedTreeBinding $preparedPaperRoot
    if ($actual.sha256 -cne $expectedTreeSha256 -or
            $actual.file_count -ne $expectedEntries.Count -or
            $actual.total_size -ne $expectedTotalSize) {
        throw 'PLATFORM_SMOKE_PREPARED_TARGET_TREE_CONTENT_MISMATCH'
    }
    return [pscustomobject]@{
        manifest_sha256 = Get-Sha256 $manifestPath
        tree_sha256 = $expectedTreeSha256
        file_count = [int]$expectedEntries.Count
        total_size = $expectedTotalSize
    }
}

function Get-ImmutableInputSnapshot {
    $currentScriptSha256 = Get-Sha256 (Assert-DirectLocalPath $PSCommandPath)
    if ($currentScriptSha256 -cne $executedScriptSha256) {
        throw 'PLATFORM_SMOKE_EXECUTED_SCRIPT_CHANGED'
    }
    $rootJava = Resolve-RootJava21
    $targetJava = Resolve-TargetJava
    $gradle = Resolve-OfflineGradle961
    $serverAssets = Resolve-ServerMatrixAssets
    if ([string]$serverAssets.prepared_root -cne $preparedPaperRoot) {
        throw 'PLATFORM_SMOKE_PREPARED_PAPER_TARGET_CHANGED'
    }
    $velocityServer = Get-VerifiedArtifact $serverAssets.velocity
    $paperServer = Get-VerifiedArtifact $serverAssets.paper
    $source = Get-SourceManifestBinding
    $prepared = Get-PreparedPaperBinding
    $fabricAssets = Assert-FabricAssetCache ([bool]$WithFabricClient -or [bool]$ReportOnly)
    return [ordered]@{
        fabric_target = $FabricTarget
        minecraft_version = [string]$fabricDescriptor.minecraft_version
        fabric_api_version = [string]$fabricDescriptor.fabric_api_version
        fabric_artifact_kind = [string]$fabricDescriptor.artifact_kind
        fabric_java_major = [int]$fabricDescriptor.java_major
        fabric_runtime_mode = $fabricRuntimeMode
        script_sha256 = $executedScriptSha256
        source_manifest_sha256 = $source.sha256
        source_file_count = $source.file_count
        velocity_server_sha256 = Get-Sha256 $velocityServer
        paper_server_sha256 = Get-Sha256 $paperServer
        server_matrix_manifest_sha256 = $serverAssets.manifest_sha256
        paper_prepared_manifest_sha256 = $prepared.manifest_sha256
        paper_prepared_tree_sha256 = $prepared.tree_sha256
        paper_prepared_file_count = $prepared.file_count
        paper_prepared_total_size = $prepared.total_size
        fabric_asset_cache_verified = [bool]$fabricAssets.fabric_asset_cache_verified
        fabric_version_info_sha1 = [string]$fabricAssets.fabric_version_info_sha1
        fabric_version_info_sha256 = [string]$fabricAssets.fabric_version_info_sha256
        fabric_asset_index_id = [string]$fabricAssets.fabric_asset_index_id
        fabric_asset_index_sha1 = [string]$fabricAssets.fabric_asset_index_sha1
        fabric_asset_index_sha256 = [string]$fabricAssets.fabric_asset_index_sha256
        fabric_asset_index_size = [long]$fabricAssets.fabric_asset_index_size
        fabric_asset_object_manifest_sha256 = [string]$fabricAssets.fabric_asset_object_manifest_sha256
        fabric_asset_object_count = [int]$fabricAssets.fabric_asset_object_count
        fabric_asset_object_total_size = [long]$fabricAssets.fabric_asset_object_total_size
        root_java_executable_sha256 = $rootJava.sha256
        root_java_file_version = $rootJava.file_version
        target_java_executable_sha256 = $targetJava.sha256
        target_java_file_version = $targetJava.file_version
        gradle_version = $gradle.version
        gradle_launcher_sha256 = $gradle.launcher_sha256
        gradle_core_sha256 = $gradle.core_sha256
    }
}

function Get-CurrentEvidenceBinding {
    $input = Get-ImmutableInputSnapshot
    foreach ($artifact in @($fabricArtifactJar, $fabricRuntimeArtifactJar, $velocityPlugin, $paperPlugin)) {
        $null = Assert-DirectLocalPath $artifact
    }
    $fabricIdentity = Get-FabricArtifactIdentity $fabricArtifactJar $fabricDescriptor
    $current = [ordered]@{}
    foreach ($name in @($input.Keys)) { $current[$name] = $input[$name] }
    $current['fabric_artifact_sha256'] = Get-Sha256 $fabricArtifactJar
    $current['fabric_runtime_artifact_sha256'] = Get-Sha256 $fabricRuntimeArtifactJar
    $current['fabric_build_id'] = $fabricIdentity.build_id
    $current['velocity_policy_minecraft_versions'] = [string]$fabricDescriptor.minecraft_version
    $current['velocity_policy_client_build_ids'] = $fabricIdentity.build_id
    $current['velocity_plugin_sha256'] = Get-Sha256 $velocityPlugin
    $current['paper_plugin_sha256'] = Get-Sha256 $paperPlugin
    return $current
}

function Get-RunLocalRuntimeBinding {
    $prepared = Get-PreparedTreeBinding $paperRoot
    return [ordered]@{
        velocity_server_sha256 = Get-Sha256 (Assert-DirectLocalPath (Join-Path $velocityRoot 'velocity.jar'))
        paper_server_sha256 = Get-Sha256 (Assert-DirectLocalPath (Join-Path $paperRoot 'paper.jar'))
        velocity_plugin_sha256 = Get-Sha256 (Assert-DirectLocalPath (Join-Path $velocityRoot 'plugins\mcace.jar'))
        paper_plugin_sha256 = Get-Sha256 (Assert-DirectLocalPath (Join-Path $paperRoot 'plugins\mcace.jar'))
        paper_prepared_tree_sha256 = $prepared.sha256
        paper_prepared_file_count = $prepared.file_count
        paper_prepared_total_size = $prepared.total_size
    }
}

function Assert-RunLocalRuntimeBinding(
        [System.Collections.IDictionary]$Actual,
        [System.Collections.IDictionary]$Expected) {
    foreach ($name in @('velocity_server_sha256', 'paper_server_sha256',
            'velocity_plugin_sha256', 'paper_plugin_sha256', 'paper_prepared_tree_sha256')) {
        if ([string]$Actual[$name] -cne [string]$Expected[$name]) {
            throw "PLATFORM_SMOKE_RUN_LOCAL_RUNTIME_MISMATCH: $name"
        }
    }
    foreach ($name in @('paper_prepared_file_count', 'paper_prepared_total_size')) {
        if ([long]$Actual[$name] -ne [long]$Expected[$name]) {
            throw "PLATFORM_SMOKE_RUN_LOCAL_RUNTIME_MISMATCH: $name"
        }
    }
}

function Get-JsonPropertyNames([object]$Value) {
    return @($Value.PSObject.Properties | ForEach-Object Name)
}

function Test-ExactJsonProperties([object]$Value, [string[]]$Expected) {
    $actual = @(Get-JsonPropertyNames $Value | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    return $actual.Count -eq $wanted.Count -and (($actual -join "`n") -ceq ($wanted -join "`n"))
}

function Test-JsonInteger([object]$Value) {
    return $Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64]
}

function Assert-SanitizedJson([string]$Raw) {
    if ($Raw.Length -gt 65536 -or
            $Raw -match '(?i)[A-Z]:[\\/]|\\\\|(?:^|["\s])/(?:home|users|tmp|var|opt|mnt|root)/' -or
            $Raw -match '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b') {
        throw 'PLATFORM_SMOKE_EVIDENCE_NOT_SANITIZED'
    }
}

function Open-LockedEvidence([string]$Path) {
    $resolved = Assert-DirectLocalPath $Path
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($resolved, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        if ($stream.Length -le 0 -or $stream.Length -gt 65536) {
            throw 'PLATFORM_SMOKE_EVIDENCE_SIZE_INVALID'
        }
        $memory = [System.IO.MemoryStream]::new()
        try { $stream.CopyTo($memory); $bytes = $memory.ToArray() }
        finally { $memory.Dispose() }
        $raw = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        Assert-SanitizedJson $raw
        return [pscustomobject]@{ raw = $raw; sha256 = Get-BytesSha256 $bytes; stream = $stream }
    } catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}

function Assert-PassingReportRaw([string]$Raw, [switch]$RequireFullFabricEvidence) {
    $names = @('schema', 'generated_at', 'artifact_class', 'status', 'release_evidence',
        'diagnostics_retained', 'fabric_target', 'minecraft_version', 'fabric_api_version',
        'velocity_policy_minecraft_versions', 'velocity_policy_client_build_ids',
        'fabric_artifact_kind', 'fabric_java_major', 'fabric_runtime_mode',
        'fabric_runtime_jar_loaded', 'fabric_release_jar_loaded',
        'fabric_client_requested', 'fabric_evidence_requested', 'explicit_file_fixture_present',
        'enablement_consent_requested', 'enablement_consent_rendered', 'enablement_consent_accepted',
        'explicit_file_manifest_entries', 'explicit_file_manifest_entries_observed',
        'explicit_file_consent_requested', 'explicit_file_consent_rendered',
        'explicit_file_consent_accepted', 'fabric_authenticated', 'game_render_frame_requested',
        'game_render_frame_consent_rendered', 'game_render_frame_consent_allowed',
        'game_render_frame_consent_inherited',
        'game_render_frame_completed', 'fabric_gui_coverage', 'fabric_evidence_coverage',
        'raw_evidence_retained', 'evidence_audit_summary_observed', 'persistent_identity_unchanged',
        'velocity_transport_classes_present', 'paper_admission_channel_enabled',
        'paper_missing_pin_failure_observed', 'paper_missing_pin_plugin_disabled',
        'paper_missing_pin_channel_absent', 'loopback_listener_count', 'assertion_count',
        'cleanup_completed', 'cleanup_ports_free', 'remaining_owned_process_count')
    try { $report = $Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'PLATFORM_SMOKE_REPORT_JSON_INVALID' }
    if (-not (Test-ExactJsonProperties $report $names)) { throw 'PLATFORM_SMOKE_REPORT_SCHEMA_INVALID' }
    $timestampMatch = [regex]::Match(
        $Raw, '"generated_at"\s*:\s*"(?<timestamp>[^"\\]+)"',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $timestampMatch.Success) { throw 'PLATFORM_SMOKE_REPORT_TIMESTAMP_INVALID' }
    $timestamp = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact($timestampMatch.Groups['timestamp'].Value, 'o',
            [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None,
            [ref]$timestamp)) { throw 'PLATFORM_SMOKE_REPORT_TIMESTAMP_INVALID' }
    $age = [DateTimeOffset]::UtcNow - $timestamp
    if ($age.TotalMinutes -lt 0 -or $age.TotalMinutes -gt $MaximumReportAgeMinutes) {
        throw 'PLATFORM_SMOKE_REPORT_STALE'
    }
    $requiredTrue = @('persistent_identity_unchanged', 'velocity_transport_classes_present', 'paper_admission_channel_enabled',
        'paper_missing_pin_failure_observed', 'paper_missing_pin_plugin_disabled',
        'paper_missing_pin_channel_absent', 'cleanup_completed', 'cleanup_ports_free')
    foreach ($name in $requiredTrue) {
        if ($report.$name -isnot [bool] -or -not $report.$name) {
            throw "PLATFORM_SMOKE_REPORT_ASSERTION_INVALID: $name"
        }
    }
    foreach ($name in @('release_evidence', 'diagnostics_retained', 'fabric_runtime_jar_loaded',
            'fabric_release_jar_loaded', 'raw_evidence_retained')) {
        if ($report.$name -isnot [bool]) { throw "PLATFORM_SMOKE_REPORT_TYPE_INVALID: $name" }
    }
    foreach ($name in @('fabric_client_requested', 'fabric_evidence_requested',
            'explicit_file_fixture_present', 'enablement_consent_requested',
            'enablement_consent_rendered', 'enablement_consent_accepted',
            'explicit_file_manifest_entries_observed',
            'explicit_file_consent_requested', 'explicit_file_consent_rendered',
            'explicit_file_consent_accepted', 'fabric_authenticated', 'game_render_frame_requested',
            'game_render_frame_consent_rendered', 'game_render_frame_consent_allowed',
            'game_render_frame_consent_inherited',
            'game_render_frame_completed', 'fabric_gui_coverage', 'fabric_evidence_coverage',
            'evidence_audit_summary_observed')) {
        if ($report.$name -isnot [bool]) { throw "PLATFORM_SMOKE_REPORT_TYPE_INVALID: $name" }
    }
    $guiFields = @('explicit_file_fixture_present', 'enablement_consent_requested',
        'enablement_consent_rendered', 'enablement_consent_accepted',
        'explicit_file_manifest_entries_observed',
        'explicit_file_consent_requested', 'explicit_file_consent_rendered',
        'explicit_file_consent_accepted', 'fabric_authenticated', 'fabric_gui_coverage')
    $evidenceFields = @('game_render_frame_requested', 'game_render_frame_consent_allowed',
        'game_render_frame_consent_inherited',
        'game_render_frame_completed',
        'fabric_evidence_coverage', 'evidence_audit_summary_observed')
    foreach ($name in $guiFields) {
        if ([bool]$report.$name -ne [bool]$report.fabric_client_requested) {
            throw "PLATFORM_SMOKE_REPORT_GUI_BOUNDARY_INVALID: $name"
        }
    }
    foreach ($name in $evidenceFields) {
        if ([bool]$report.$name -ne [bool]$report.fabric_evidence_requested) {
            throw "PLATFORM_SMOKE_REPORT_EVIDENCE_BOUNDARY_INVALID: $name"
        }
    }
    if ([bool]$report.game_render_frame_consent_rendered -and
            [bool]$report.game_render_frame_consent_inherited) {
        throw 'PLATFORM_SMOKE_REPORT_GAME_RENDER_FRAME_RENDERED_AND_INHERITED'
    }
    if ([bool]$report.game_render_frame_consent_rendered) {
        throw 'PLATFORM_SMOKE_REPORT_GAME_RENDER_FRAME_RENDERED_INVALID'
    }
    if ($report.fabric_evidence_requested -and -not $report.fabric_client_requested) {
        throw 'PLATFORM_SMOKE_REPORT_EVIDENCE_WITHOUT_CLIENT_INVALID'
    }
    if ($RequireFullFabricEvidence -and
            (-not $report.fabric_client_requested -or -not $report.fabric_evidence_requested)) {
        throw 'PLATFORM_SMOKE_FULL_FABRIC_EVIDENCE_REQUIRED'
    }
    if ($report.schema -ne $reportSchema -or $report.artifact_class -cne $fabricArtifactClass -or
            $report.status -cne 'passed' -or $report.fabric_target -cne $FabricTarget -or
            $report.minecraft_version -cne [string]$fabricDescriptor.minecraft_version -or
            $report.velocity_policy_minecraft_versions -cne [string]$fabricDescriptor.minecraft_version -or
            $report.velocity_policy_minecraft_versions -cne $report.minecraft_version -or
            [string]$report.velocity_policy_client_build_ids -cnotmatch
                '^platform-smoke-[0-9]{8}T[0-9]{9}Z$' -or
            $report.fabric_api_version -cne [string]$fabricDescriptor.fabric_api_version -or
            $report.fabric_artifact_kind -cne [string]$fabricDescriptor.artifact_kind -or
            -not (Test-JsonInteger $report.fabric_java_major) -or
            [int]$report.fabric_java_major -ne [int]$fabricDescriptor.java_major -or
            $report.fabric_runtime_mode -cne $fabricRuntimeMode -or
            $report.release_evidence -or $report.raw_evidence_retained -or
            ([bool]$report.fabric_runtime_jar_loaded -ne [bool]$report.fabric_client_requested) -or
            ($report.fabric_release_jar_loaded -and -not $report.fabric_runtime_jar_loaded) -or
            ($RequireFullFabricEvidence -and -not $report.fabric_runtime_jar_loaded) -or
            -not (Test-JsonInteger $report.explicit_file_manifest_entries) -or
            $report.explicit_file_manifest_entries -ne $(if ($report.fabric_client_requested) { 1 } else { 0 }) -or
            -not (Test-JsonInteger $report.loopback_listener_count) -or
            $report.loopback_listener_count -ne 2 -or -not (Test-JsonInteger $report.assertion_count) -or
            $report.assertion_count -lt $(if ($RequireFullFabricEvidence) { 13 } else { 6 }) -or
            -not (Test-JsonInteger $report.remaining_owned_process_count) -or
            $report.remaining_owned_process_count -ne 0) {
        throw 'PLATFORM_SMOKE_REPORT_INVALID'
    }
    return $report
}

function Assert-BindingRaw([string]$Raw, [string]$ReportSha256, [object]$Report,
        [System.Collections.IDictionary]$Current) {
    $names = @('schema', 'report_schema', 'report_generated_at', 'report_sha256', 'source_mode',
        'fabric_target', 'minecraft_version', 'velocity_policy_minecraft_versions',
        'velocity_policy_client_build_ids', 'fabric_api_version', 'fabric_artifact_kind',
        'fabric_java_major', 'fabric_runtime_mode', 'fabric_runtime_jar_loaded',
        'fabric_release_jar_loaded',
        'fabric_artifact_marker_observed', 'fabric_build_id', 'script_sha256',
        'source_manifest_sha256', 'source_file_count', 'fabric_artifact_sha256',
        'fabric_runtime_artifact_sha256',
        'velocity_plugin_sha256', 'paper_plugin_sha256', 'velocity_server_sha256',
        'paper_server_sha256', 'server_matrix_manifest_sha256',
        'paper_prepared_manifest_sha256', 'paper_prepared_tree_sha256',
        'paper_prepared_file_count', 'paper_prepared_total_size',
        'fabric_asset_cache_verified', 'fabric_version_info_sha1',
        'fabric_version_info_sha256', 'fabric_asset_index_id', 'fabric_asset_index_sha1',
        'fabric_asset_index_sha256', 'fabric_asset_index_size',
        'fabric_asset_object_manifest_sha256', 'fabric_asset_object_count',
        'fabric_asset_object_total_size',
        'root_java_executable_sha256', 'root_java_file_version',
        'target_java_executable_sha256', 'target_java_file_version', 'gradle_version',
        'gradle_launcher_sha256', 'gradle_core_sha256', 'passed')
    try { $binding = $Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'PLATFORM_SMOKE_BINDING_JSON_INVALID' }
    if (-not (Test-ExactJsonProperties $binding $names)) { throw 'PLATFORM_SMOKE_BINDING_SCHEMA_INVALID' }
    if ($binding.schema -cne $bindingSchema -or $binding.report_schema -ne $reportSchema -or
            $binding.report_generated_at -cne $Report.generated_at -or
            $binding.report_sha256 -cne $ReportSha256 -or $binding.source_mode -cne 'EXECUTED' -or
            $binding.fabric_target -cne $FabricTarget -or
            $binding.fabric_target -cne $Report.fabric_target -or
            $binding.minecraft_version -cne [string]$fabricDescriptor.minecraft_version -or
            $binding.minecraft_version -cne $Report.minecraft_version -or
            $binding.velocity_policy_minecraft_versions -cne [string]$fabricDescriptor.minecraft_version -or
            $binding.velocity_policy_minecraft_versions -cne $Report.velocity_policy_minecraft_versions -or
            $binding.velocity_policy_client_build_ids -cne $Report.velocity_policy_client_build_ids -or
            $binding.velocity_policy_client_build_ids -cne $binding.fabric_build_id -or
            $binding.fabric_api_version -cne [string]$fabricDescriptor.fabric_api_version -or
            $binding.fabric_api_version -cne $Report.fabric_api_version -or
            $binding.fabric_artifact_kind -cne [string]$fabricDescriptor.artifact_kind -or
            $binding.fabric_artifact_kind -cne $Report.fabric_artifact_kind -or
            -not (Test-JsonInteger $binding.fabric_java_major) -or
            [int]$binding.fabric_java_major -ne [int]$fabricDescriptor.java_major -or
            [int]$binding.fabric_java_major -ne [int]$Report.fabric_java_major -or
            $binding.fabric_runtime_mode -cne $fabricRuntimeMode -or
            $binding.fabric_runtime_jar_loaded -isnot [bool] -or
            [bool]$binding.fabric_runtime_jar_loaded -ne [bool]$Report.fabric_runtime_jar_loaded -or
            $binding.fabric_release_jar_loaded -isnot [bool] -or
            [bool]$binding.fabric_release_jar_loaded -ne [bool]$Report.fabric_release_jar_loaded -or
            $binding.fabric_artifact_marker_observed -isnot [bool] -or
            [bool]$binding.fabric_artifact_marker_observed -ne [bool]$Report.fabric_runtime_jar_loaded -or
            [string]$binding.fabric_build_id -cnotmatch '^platform-smoke-[0-9]{8}T[0-9]{9}Z$' -or
            $binding.passed -isnot [bool] -or -not $binding.passed -or
            $binding.fabric_asset_cache_verified -isnot [bool] -or
            -not (Test-JsonInteger $binding.source_file_count) -or
            -not (Test-JsonInteger $binding.paper_prepared_file_count) -or
            -not (Test-JsonInteger $binding.paper_prepared_total_size) -or
            -not (Test-JsonInteger $binding.fabric_asset_index_size) -or
            -not (Test-JsonInteger $binding.fabric_asset_object_count) -or
            -not (Test-JsonInteger $binding.fabric_asset_object_total_size) -or
            [string]$binding.paper_prepared_manifest_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$binding.paper_prepared_tree_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$binding.fabric_version_info_sha1 -cne [string]$fabricDescriptor.version_info_sha1 -or
            [string]$binding.fabric_version_info_sha256 -cne [string]$fabricDescriptor.version_info_sha256 -or
            [string]$binding.fabric_asset_index_id -cne [string]$fabricDescriptor.asset_index -or
            [string]$binding.fabric_asset_index_sha1 -cne [string]$fabricDescriptor.asset_index_sha1 -or
            [long]$binding.fabric_asset_index_size -ne [long]$fabricDescriptor.asset_index_size) {
        throw 'PLATFORM_SMOKE_BINDING_INVALID'
    }
    if ([bool]$Report.fabric_client_requested) {
        if (-not [bool]$binding.fabric_asset_cache_verified -or
                [string]$binding.fabric_asset_index_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                [string]$binding.fabric_asset_object_manifest_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                [int]$binding.fabric_asset_object_count -le 0 -or
                [long]$binding.fabric_asset_object_total_size -le 0L) {
            throw 'PLATFORM_SMOKE_BINDING_FABRIC_ASSET_CACHE_INVALID'
        }
    } elseif ([bool]$binding.fabric_asset_cache_verified -or
            -not [string]::IsNullOrEmpty([string]$binding.fabric_asset_index_sha256) -or
            -not [string]::IsNullOrEmpty([string]$binding.fabric_asset_object_manifest_sha256) -or
            [int]$binding.fabric_asset_object_count -ne 0 -or
            [long]$binding.fabric_asset_object_total_size -ne 0L) {
        throw 'PLATFORM_SMOKE_BINDING_UNREQUESTED_FABRIC_ASSET_CACHE_INVALID'
    }
    foreach ($name in @('fabric_target', 'minecraft_version', 'fabric_api_version',
            'velocity_policy_minecraft_versions', 'velocity_policy_client_build_ids',
            'fabric_artifact_kind', 'fabric_runtime_mode', 'fabric_build_id', 'script_sha256',
            'source_manifest_sha256', 'fabric_artifact_sha256', 'fabric_runtime_artifact_sha256',
            'velocity_plugin_sha256', 'paper_plugin_sha256', 'velocity_server_sha256',
            'paper_server_sha256', 'server_matrix_manifest_sha256',
            'paper_prepared_manifest_sha256', 'paper_prepared_tree_sha256',
            'fabric_version_info_sha1', 'fabric_version_info_sha256',
            'fabric_asset_index_id', 'fabric_asset_index_sha1', 'fabric_asset_index_sha256',
            'fabric_asset_object_manifest_sha256', 'root_java_executable_sha256',
            'root_java_file_version', 'target_java_executable_sha256',
            'target_java_file_version', 'gradle_version', 'gradle_launcher_sha256',
            'gradle_core_sha256')) {
        if ([string]$binding.$name -cne [string]$Current[$name]) {
            throw "PLATFORM_SMOKE_BINDING_CURRENT_MISMATCH: $name"
        }
    }
    if ($binding.fabric_java_major -ne $Current.fabric_java_major -or
            $binding.source_file_count -ne $Current.source_file_count -or
            $binding.paper_prepared_file_count -ne $Current.paper_prepared_file_count -or
            $binding.paper_prepared_total_size -ne $Current.paper_prepared_total_size -or
            $binding.fabric_asset_index_size -ne $Current.fabric_asset_index_size -or
            $binding.fabric_asset_object_count -ne $Current.fabric_asset_object_count -or
            $binding.fabric_asset_object_total_size -ne $Current.fabric_asset_object_total_size -or
            [bool]$binding.fabric_asset_cache_verified -ne [bool]$Current.fabric_asset_cache_verified) {
        throw 'PLATFORM_SMOKE_BINDING_CURRENT_COUNT_MISMATCH'
    }
}

function Assert-EvidencePair([string]$ReportPath, [System.Collections.IDictionary]$Current,
        [switch]$RequireFullFabricEvidence) {
    $reportEvidence = $null
    $bindingEvidence = $null
    try {
        $reportEvidence = Open-LockedEvidence $ReportPath
        $bindingPath = Join-Path (Split-Path -Parent $ReportPath) 'binding.json'
        $bindingEvidence = Open-LockedEvidence $bindingPath
        $report = Assert-PassingReportRaw $reportEvidence.raw -RequireFullFabricEvidence:$RequireFullFabricEvidence
        Assert-BindingRaw $bindingEvidence.raw $reportEvidence.sha256 $report $Current
        return $report
    } finally {
        if ($null -ne $bindingEvidence) { $bindingEvidence.stream.Dispose() }
        if ($null -ne $reportEvidence) { $reportEvidence.stream.Dispose() }
    }
}

function Get-LatestEvidenceReport {
    $runs = $runsRoot
    if (-not (Test-Path -LiteralPath $runs -PathType Container)) { return $null }
    $runs = Assert-DirectLocalPath $runs -Directory
    $targetLeafSegment = '-' + $FabricTarget.Replace('.', '_') + '-'
    $candidates = @(Get-ChildItem -LiteralPath $runs -Directory -Force |
        Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
            (Test-SmokeRunLeaf $_.Name) -and
            $_.Name.Contains($targetLeafSegment) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'report.json') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'binding.json') -PathType Leaf)
        } |
        ForEach-Object { Get-Item -LiteralPath (Join-Path $_.FullName 'report.json') } |
        Sort-Object LastWriteTimeUtc -Descending)
    foreach ($candidate in $candidates) {
        try {
            $summary = Get-Content -LiteralPath $candidate.FullName -Raw -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            if ($summary.fabric_target -ceq $FabricTarget -and
                    $summary.fabric_client_requested -eq $true -and
                    $summary.fabric_evidence_requested -eq $true) {
                return $candidate.FullName
            }
        } catch {
            # Selection is advisory; the selected pair is strictly locked and validated below.
        }
    }
    return $null
}

function New-EvidenceBinding([byte[]]$ReportBytes, [object]$Report,
        [System.Collections.IDictionary]$Current) {
    return [ordered]@{
        schema = $bindingSchema
        report_schema = $reportSchema
        report_generated_at = $Report.generated_at
        report_sha256 = Get-BytesSha256 $ReportBytes
        source_mode = 'EXECUTED'
        fabric_target = $Current.fabric_target
        minecraft_version = $Current.minecraft_version
        velocity_policy_minecraft_versions = $Current.velocity_policy_minecraft_versions
        velocity_policy_client_build_ids = $Current.velocity_policy_client_build_ids
        fabric_api_version = $Current.fabric_api_version
        fabric_artifact_kind = $Current.fabric_artifact_kind
        fabric_java_major = [int]$Current.fabric_java_major
        fabric_runtime_mode = $Current.fabric_runtime_mode
        fabric_runtime_jar_loaded = [bool]$Report.fabric_runtime_jar_loaded
        fabric_release_jar_loaded = [bool]$Report.fabric_release_jar_loaded
        fabric_artifact_marker_observed = [bool]$Report.fabric_runtime_jar_loaded
        fabric_build_id = $Current.fabric_build_id
        script_sha256 = $Current.script_sha256
        source_manifest_sha256 = $Current.source_manifest_sha256
        source_file_count = $Current.source_file_count
        fabric_artifact_sha256 = $Current.fabric_artifact_sha256
        fabric_runtime_artifact_sha256 = $Current.fabric_runtime_artifact_sha256
        velocity_plugin_sha256 = $Current.velocity_plugin_sha256
        paper_plugin_sha256 = $Current.paper_plugin_sha256
        velocity_server_sha256 = $Current.velocity_server_sha256
        paper_server_sha256 = $Current.paper_server_sha256
        server_matrix_manifest_sha256 = $Current.server_matrix_manifest_sha256
        paper_prepared_manifest_sha256 = $Current.paper_prepared_manifest_sha256
        paper_prepared_tree_sha256 = $Current.paper_prepared_tree_sha256
        paper_prepared_file_count = $Current.paper_prepared_file_count
        paper_prepared_total_size = $Current.paper_prepared_total_size
        fabric_asset_cache_verified = [bool]$Current.fabric_asset_cache_verified
        fabric_version_info_sha1 = $Current.fabric_version_info_sha1
        fabric_version_info_sha256 = $Current.fabric_version_info_sha256
        fabric_asset_index_id = $Current.fabric_asset_index_id
        fabric_asset_index_sha1 = $Current.fabric_asset_index_sha1
        fabric_asset_index_sha256 = $Current.fabric_asset_index_sha256
        fabric_asset_index_size = $Current.fabric_asset_index_size
        fabric_asset_object_manifest_sha256 = $Current.fabric_asset_object_manifest_sha256
        fabric_asset_object_count = $Current.fabric_asset_object_count
        fabric_asset_object_total_size = $Current.fabric_asset_object_total_size
        root_java_executable_sha256 = $Current.root_java_executable_sha256
        root_java_file_version = $Current.root_java_file_version
        target_java_executable_sha256 = $Current.target_java_executable_sha256
        target_java_file_version = $Current.target_java_file_version
        gradle_version = $Current.gradle_version
        gradle_launcher_sha256 = $Current.gradle_launcher_sha256
        gradle_core_sha256 = $Current.gradle_core_sha256
        passed = $true
    }
}

function Assert-BindingSnapshotUnchanged(
        [System.Collections.IDictionary]$Before,
        [System.Collections.IDictionary]$After) {
    foreach ($name in @($Before.Keys)) {
        if ([string]$Before[$name] -cne [string]$After[$name]) {
            throw "PLATFORM_SMOKE_CURRENT_INPUT_CHANGED_DURING_RUN: $name"
        }
    }
}

$script:ServerAssets = Resolve-ServerMatrixAssets
$preparedPaperRoot = [string]$script:ServerAssets.prepared_root

if ($ReportOnly) {
    $currentEvidenceBinding = Get-CurrentEvidenceBinding
    if ($currentEvidenceBinding.fabric_artifact_sha256 -cne
            $ExpectedFabricArtifactSha256.ToLowerInvariant() -or
            $currentEvidenceBinding.velocity_plugin_sha256 -cne
            $ExpectedVelocityPluginSha256.ToLowerInvariant() -or
            $currentEvidenceBinding.paper_plugin_sha256 -cne
            $ExpectedPaperPluginSha256.ToLowerInvariant() -or
            $currentEvidenceBinding.velocity_server_sha256 -cne
            $ExpectedVelocityServerSha256.ToLowerInvariant() -or
            $currentEvidenceBinding.paper_server_sha256 -cne
            $ExpectedPaperServerSha256.ToLowerInvariant() -or
            $currentEvidenceBinding.paper_prepared_manifest_sha256 -cne
            $ExpectedPaperPreparedManifestSha256.ToLowerInvariant() -or
            $currentEvidenceBinding.paper_prepared_tree_sha256 -cne
            $ExpectedPaperPreparedTreeSha256.ToLowerInvariant() -or
            $currentEvidenceBinding.fabric_version_info_sha256 -cne
            $ExpectedFabricVersionInfoSha256.ToLowerInvariant() -or
            $currentEvidenceBinding.fabric_asset_index_sha256 -cne
            $ExpectedFabricAssetIndexSha256.ToLowerInvariant() -or
            $currentEvidenceBinding.fabric_asset_object_manifest_sha256 -cne
            $ExpectedFabricAssetObjectManifestSha256.ToLowerInvariant()) {
        throw 'PLATFORM_SMOKE_REPORT_ONLY_EXPECTED_PRODUCT_HASH_MISMATCH'
    }
    $latestReport = Get-LatestEvidenceReport
    if ($null -eq $latestReport) { throw 'PLATFORM_SMOKE_PASSING_EVIDENCE_PAIR_REQUIRED' }
    $null = Assert-EvidencePair $latestReport $currentEvidenceBinding -RequireFullFabricEvidence
    Write-Output "PLATFORM_LOAD_SMOKE_PASS|report-only|target=$FabricTarget"
    exit 0
}

$script:RootJava = Resolve-RootJava21
$script:TargetJava = Resolve-TargetJava
$script:RootJavaPath = $script:RootJava.path
$script:TargetJavaPath = $script:TargetJava.path
$script:OfflineGradle = Resolve-OfflineGradle961
$repoRoot = Assert-DirectLocalPath $repoRoot -Directory
$buildRoot = Initialize-SafeOwnedDirectory $buildRoot $repoRoot
$smokeRoot = Initialize-SafeOwnedDirectory $smokeRoot $buildRoot
$runsRoot = Initialize-SafeOwnedDirectory $runsRoot $smokeRoot
$cacheRoot = Initialize-SafeOwnedDirectory $cacheRoot $smokeRoot
$velocityServerJar = Get-VerifiedArtifact $script:ServerAssets.velocity
$paperServerJar = Get-VerifiedArtifact $script:ServerAssets.paper
$preBuildInputSnapshot = Get-ImmutableInputSnapshot
Assert-SmokeRunLeaf $runLeaf
$runRoot = New-ExclusiveOwnedDirectory $runRoot $runsRoot
$velocityRoot = New-ExclusiveOwnedDirectory $velocityRoot $runRoot
$paperRoot = New-ExclusiveOwnedDirectory $paperRoot $runRoot

$smokeBuildProperties = @(
    '-PmcaceSmokeArtifactMode=true',
    "-PmcaceClientBuildId=$fabricSmokeBuildId",
    "-PmcaceSmokeRunToken=$runToken"
)
$rootBuildTasks = @(':mcace-server-velocity:shadowJar', ':mcace-server-paper:shadowJar')
if ([int]$fabricDescriptor.java_major -eq 21) {
    $rootBuildTasks += [string]$fabricDescriptor.build_task
    $rootBuildTasks += ':mcace-client-fabric:smokeNamedJar'
} else {
    $rootBuildTasks += ':stageModernFabricDeps'
}
Invoke-PinnedOfflineGradle $script:RootJavaPath $repoRoot $rootBuildTasks `
    $smokeBuildProperties $true 'PLATFORM_SMOKE_ROOT_JDK21_BUILD_FAILED'

if ([int]$fabricDescriptor.java_major -eq 25) {
    $modernProperties = @($smokeBuildProperties) + @(
        "-PmcaceRootDepsDir=$stagedModernDependencies",
        "-PmcaceProductVersion=$fabricArtifactVersion"
    )
    Invoke-PinnedOfflineGradle $script:TargetJavaPath ([string]$fabricDescriptor.gradle_project_directory) `
        @([string]$fabricDescriptor.build_task) $modernProperties $true `
        'PLATFORM_SMOKE_MODERN_JDK25_BUILD_FAILED'
}

if (-not (Test-Path -LiteralPath $velocityPlugin) -or -not (Test-Path -LiteralPath $paperPlugin) -or
        -not (Test-Path -LiteralPath $fabricArtifactJar) -or
        -not (Test-Path -LiteralPath $fabricRuntimeArtifactJar)) {
    throw 'Expected MCAce platform artifacts were not produced'
}
$builtFabricArtifactSha256 = Get-Sha256 (Assert-DirectLocalPath $fabricArtifactJar)
$builtFabricRuntimeArtifactSha256 = Get-Sha256 (Assert-DirectLocalPath $fabricRuntimeArtifactJar)
$verificationProperties = @($smokeBuildProperties) + @(
    "-PmcaceSmokeExpectedArtifactSha256=$builtFabricRuntimeArtifactSha256"
)
if ([int]$fabricDescriptor.java_major -eq 25) {
    $verificationProperties += @(
        "-PmcaceRootDepsDir=$stagedModernDependencies",
        "-PmcaceProductVersion=$fabricArtifactVersion"
    )
}
Invoke-PinnedOfflineGradle $script:TargetJavaPath ([string]$fabricDescriptor.gradle_project_directory) `
    @([string]$fabricDescriptor.verify_task) $verificationProperties $false `
    'PLATFORM_SMOKE_FABRIC_ARTIFACT_VERIFY_FAILED'
$currentEvidenceBinding = Get-CurrentEvidenceBinding
Assert-BindingSnapshotUnchanged $preBuildInputSnapshot $currentEvidenceBinding
if ($currentEvidenceBinding.fabric_build_id -cne $fabricSmokeBuildId) {
    throw 'PLATFORM_SMOKE_BUILT_FABRIC_IDENTITY_MISMATCH'
}
$fabricExpectedArtifactMarker =
    "MCACE_FABRIC_ARTIFACT_LOADED version=$fabricArtifactVersion build_id=$fabricSmokeBuildId" +
    " code_source_sha256=$($currentEvidenceBinding.fabric_runtime_artifact_sha256)"
$velocityTransportClassesPresent = Test-JarEntry $velocityPlugin 'com/ellan/mcace/velocity/MCAceVelocityChannels.class'
if (-not $velocityTransportClassesPresent) {
    throw 'Velocity MCAce plugin artifact is missing its client transport channel implementation'
}

$proxyPort = Get-FreeLoopbackPort
$paperPort = Get-FreeLoopbackPort
while ($paperPort -eq $proxyPort) {
    $paperPort = Get-FreeLoopbackPort
}

$velocityPlugins = Join-Path $velocityRoot 'plugins'
$paperPlugins = Join-Path $paperRoot 'plugins'
$velocityPlugins = New-ExclusiveOwnedDirectory $velocityPlugins $velocityRoot
$paperPlugins = New-ExclusiveOwnedDirectory $paperPlugins $paperRoot
Copy-Item -LiteralPath $velocityPlugin -Destination (Join-Path $velocityPlugins 'mcace.jar')
Copy-Item -LiteralPath $paperPlugin -Destination (Join-Path $paperPlugins 'mcace.jar')
Copy-Item -LiteralPath $velocityServerJar -Destination (Join-Path $velocityRoot 'velocity.jar')
Copy-Item -LiteralPath $paperServerJar -Destination (Join-Path $paperRoot 'paper.jar')
foreach ($directory in @('cache', 'libraries', 'versions')) {
    $preparedDirectory = Assert-DirectLocalPath (Join-Path $preparedPaperRoot $directory) -Directory
    Copy-Item -LiteralPath $preparedDirectory -Destination $paperRoot -Recurse
}
Expand-VelocityConfiguration (Join-Path $velocityRoot 'velocity.jar') (Join-Path $velocityRoot 'velocity.toml') `
        $proxyPort $paperPort
[System.IO.File]::WriteAllText(
    (Join-Path $paperRoot 'eula.txt'),
    "eula=true`n",
    [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText(
    (Join-Path $paperRoot 'server.properties'),
    "online-mode=false`nserver-ip=127.0.0.1`nserver-port=$paperPort`nenable-query=false`nmotd=MCAce platform smoke`n",
    [System.Text.UTF8Encoding]::new($false))

$velocity = $null
$paper = $null
$fabricClient = $null
$paperPin = $null
$paperPinBackup = $null
$passed = $false
$smokeFailure = $null
$report = $null
$reportPath = $null
$cleanupCompleted = $false
$remainingOwnedProcessCount = -1
$velocityListenerPid = $null
$paperListenerPid = $null
$paperAdmissionChannelEnabled = $false
$noPlayerStartupPath = $false
$identityFingerprintBeforeRestart = $null
$identityFingerprintAfterRestart = $null
$fabricLog = $null
$fabricRoot = $null
$fabricArtifactMarkerObserved = $false
$explicitFileFixturePresent = $false
$evidenceAuditSummaryObserved = $false
$negativePinFailureObserved = $false
$negativePluginDisabled = $false
$negativeChannelMarkerAbsent = $false
$runLocalRuntimeBinding = $null
$currentAfterRun = $null
$velocityPolicyTuple = $null
$fabricConsentEvidence = [ordered]@{
    explicit_file_manifest_entries = 0
    enablement_requested = $false
    enablement_rendered = $false
    enablement_accepted = $false
    explicit_file_requested = $false
    explicit_file_rendered = $false
    explicit_file_accepted = $false
    authenticated = $false
    game_render_frame_requested = $false
    game_render_frame_rendered = $false
    game_render_frame_allowed = $false
    game_render_frame_inherited = $false
    game_render_frame_completed = $false
}
$fabricGuiStage = if ($WithFabricClient) { 'CLIENT_PENDING' } else { 'NOT_REQUESTED' }
try {
    $runLocalRuntimeBinding = Get-RunLocalRuntimeBinding
    Assert-RunLocalRuntimeBinding $runLocalRuntimeBinding $currentEvidenceBinding
    $velocity = Start-JavaService 'velocity' $velocityRoot (Join-Path $velocityRoot 'velocity.jar') '384m' @()
    $velocityLog = Join-Path $velocityRoot 'logs\latest.log'
    Wait-ServiceLog $velocity $velocityLog @(
        'MCAce Phase 2 handshake initialized',
        "Listening on /127.0.0.1:$proxyPort"
    ) 120
    $velocityListenerPid = Assert-LoopbackListener $velocity $proxyPort

    $velocityPin = Join-Path $velocityRoot 'plugins\mcace\identity\server-public-key.txt'
    if (-not (Test-Path -LiteralPath $velocityPin)) {
        throw 'Velocity did not create the MCAce server public-key pin'
    }
    $velocityPinBytes = [Convert]::FromBase64String((Get-Content -Raw -LiteralPath $velocityPin).Trim())
    if ($velocityPinBytes.Length -lt 32) {
        throw 'Velocity identity pin is not a valid Ed25519 public-key encoding'
    }
    $identityFingerprintBeforeRestart = Get-Sha256HexFromBytes $velocityPinBytes
    $velocityMCAceConfig = Join-Path $velocityRoot 'plugins\mcace\mcace.properties'
    if ($WithFabricClient) {
        $configuration = Get-Content -Raw -LiteralPath $velocityMCAceConfig
        if ($configuration -notmatch '(?m)^handshake\.timeout\.seconds=[0-9]+$') {
            throw 'Velocity MCAce configuration did not expose its bounded handshake timeout'
        }
        $configuration = $configuration -replace '(?m)^handshake\.timeout\.seconds=[0-9]+$',
            "handshake.timeout.seconds=$velocityHandshakeTimeoutSeconds"
        [System.IO.File]::WriteAllText(
            $velocityMCAceConfig, $configuration, [System.Text.UTF8Encoding]::new($false))
    }
    $velocityPolicyTuple = Set-ExactVelocityPolicyTuple `
        $velocityMCAceConfig ([string]$fabricDescriptor.minecraft_version) $fabricSmokeBuildId
    Stop-JavaService $velocity 'end'
    $velocity = $null
    if (Test-Path -LiteralPath $velocityLog) { Remove-Item -LiteralPath $velocityLog -Force }
    $velocity = Start-JavaService 'velocity-restart' $velocityRoot (Join-Path $velocityRoot 'velocity.jar') '384m' @()
    Wait-ServiceLog $velocity $velocityLog @(
        'MCAce Phase 2 handshake initialized',
        "Listening on /127.0.0.1:$proxyPort"
    ) 120
    $velocityListenerPid = Assert-LoopbackListener $velocity $proxyPort
    $restartPinBytes = [Convert]::FromBase64String((Get-Content -Raw -LiteralPath $velocityPin).Trim())
    $identityFingerprintAfterRestart = Get-Sha256HexFromBytes $restartPinBytes
    if ($identityFingerprintBeforeRestart -ne $identityFingerprintAfterRestart) {
        throw 'Velocity MCAce Ed25519 identity changed across a clean restart'
    }
    $paperData = Join-Path $paperRoot 'plugins\MCAce'
    New-Item -ItemType Directory -Force -Path $paperData | Out-Null
    $paperPin = Join-Path $paperData 'proxy-public-key.txt'
    Copy-Item -LiteralPath $velocityPin -Destination $paperPin

    $paper = Start-JavaService 'paper' $paperRoot (Join-Path $paperRoot 'paper.jar') '1024m' @('--nogui')
    $paperLog = Join-Path $paperRoot 'logs\latest.log'
    Wait-ServiceLog $paper $paperLog @(
        "Starting Minecraft server on 127.0.0.1:$paperPort",
        'MCAce signed proxy admission channel enabled',
        'Done ('
    ) 300
    $paperListenerPid = Assert-LoopbackListener $paper $paperPort
    $pinBytes = [Convert]::FromBase64String((Get-Content -Raw -LiteralPath $velocityPin).Trim())
    $pinFingerprint = Get-Sha256HexFromBytes $pinBytes
    $paperLogText = Get-Content -Raw -LiteralPath $paperLog
    $paperAdmissionChannelEnabled = Test-TextContains $paperLogText 'MCAce signed proxy admission channel enabled'
    $noPlayerStartupPath = -not $WithFabricClient
    if (-not (Test-TextContains $paperLogText $pinFingerprint ([StringComparison]::OrdinalIgnoreCase))) {
        throw 'Paper did not report the same pinned Velocity identity fingerprint'
    }
    $fabricReport = [ordered]@{
        outcome = 'SKIPPED'
        reason = 'WithFabricClient was not requested; no user Minecraft process was inspected or controlled.'
    }
    if ($WithFabricClient) {
        $fabricRoot = Join-Path $runRoot 'fabric-client'
        $fabricPinDirectory = Join-Path $fabricRoot 'config\mcace'
        New-Item -ItemType Directory -Force -Path $fabricPinDirectory, (Join-Path $fabricRoot 'mods') | Out-Null
        $serverAddress = "127.0.0.1:$proxyPort"
        $escapedPropertyAddress = $serverAddress.Replace(':', '\:')
        $pinValue = (Get-Content -Raw -LiteralPath $velocityPin).Trim()
        [System.IO.File]::WriteAllText(
            (Join-Path $fabricPinDirectory 'server-keys.properties'),
            "$escapedPropertyAddress=$pinValue`n",
            [System.Text.UTF8Encoding]::new($false))
        $explicitFileFixture = Join-Path $fabricRoot 'options.txt'
        [System.IO.File]::WriteAllText(
            $explicitFileFixture,
            "fov:0.5`nrenderDistance:8`n",
            [System.Text.UTF8Encoding]::new($false))
        $explicitFileFixturePresent = (Test-Path -LiteralPath $explicitFileFixture -PathType Leaf) -and
            (Get-Item -LiteralPath $explicitFileFixture).Length -gt 0
        if (-not $explicitFileFixturePresent) {
            throw 'Fabric explicit-file options fixture was not created'
        }
        $fabricGuiStage = 'CLIENT_STARTING'
        $fabricClient = Start-FabricClient $fabricRoot $serverAddress $WithFabricEvidence `
            $currentEvidenceBinding.fabric_runtime_artifact_sha256
        $fabricLog = Join-Path $fabricRoot 'logs\latest.log'
        Wait-ServiceLog $fabricClient $fabricLog @(
            $fabricExpectedArtifactMarker,
            'MCAce Fabric client initialized'
        ) 300
        Assert-FabricArtifactMarker $fabricLog $fabricExpectedArtifactMarker
        $fabricArtifactMarkerObserved = $true
        $fabricGuiStage = 'CLIENT_INITIALIZED'
        try {
            Wait-ServiceLog $fabricClient $fabricLog @(
                'MCAce session verified at trust level VERIFIED with risk score 0'
            ) ($manualConsentHandshakeTimeoutSeconds + 15)
        } catch {
            Update-FabricConsentEvidence $fabricConsentEvidence $fabricLog
            $fabricGuiStage = Get-FabricGuiStage $fabricConsentEvidence $fabricGuiStage
            if ([bool]$fabricConsentEvidence['enablement_rendered']) {
                throw "Fabric MCAce enablement screen rendered but was not approved before the $manualConsentHandshakeTimeoutSeconds-second smoke handshake timeout"
            }
            if ([bool]$fabricConsentEvidence['enablement_requested']) {
                throw "Fabric MCAce enablement was requested but no completed render was observed before the $manualConsentHandshakeTimeoutSeconds-second smoke handshake timeout"
            }
            throw
        }
        Update-FabricConsentEvidence $fabricConsentEvidence $fabricLog
        $fabricGuiStage = Get-FabricGuiStage $fabricConsentEvidence 'CLIENT_INITIALIZED'
        Wait-ServiceLog $fabricClient $fabricLog @(
            'MCAce explicit-file manifest prepared entries=1'
        ) 15
        Update-FabricConsentEvidence $fabricConsentEvidence $fabricLog
        if ([int]$fabricConsentEvidence['explicit_file_manifest_entries'] -ne 1) {
            throw 'Fabric did not emit the content-free explicit-file entries=1 marker for the options fixture'
        }
        if (-not (Test-FabricGuiCoverage $fabricConsentEvidence)) {
            throw 'Fabric authenticated without the complete explicit-file requested/rendered/accepted/entries=1 marker chain'
        }
        Wait-ServiceLog $paper $paperLog @(
            'Accepted signed MCAce admission state',
            'admission=VERIFIED, trust=VERIFIED, risk=0'
        ) 30
        Wait-ServiceLog $velocity $velocityLog @('MCAce verified') 30
        $observedFabricPlayerName = Get-FabricDevelopmentPlayerName $fabricLog
        if (-not [string]::IsNullOrWhiteSpace($FabricEvidencePlayerName) -and
                $FabricEvidencePlayerName -ne $observedFabricPlayerName) {
            throw 'Supplied FabricEvidencePlayerName does not match the observed local development profile'
        }
        $evidencePlayerName = if ([string]::IsNullOrWhiteSpace($FabricEvidencePlayerName)) {
            $observedFabricPlayerName
        } else {
            $FabricEvidencePlayerName
        }
        $evidenceReport = [ordered]@{
            outcome = 'NOT_REQUESTED'
            reason = 'WithFabricEvidence was not requested.'
        }
        if ($WithFabricEvidence) {
            Wait-ServiceLog $fabricClient $fabricLog @(
                'MCAce platform evidence smoke verified; waiting for a signed GAME_RENDER_FRAME request'
            ) 30
            # The console request is intentionally the only automated action. The single
            # connection-level enablement decision above covers this signed frame request; this
            # script has no cursor, window, desktop, or operating-system screen-capture API.
            $velocity.Process.StandardInput.WriteLine(
                "mcaceevidence request $evidencePlayerName frame platform-smoke-frame")
            $velocity.Process.StandardInput.Flush()
            Wait-ServiceLog $fabricClient $fabricLog @(
                'MCAce evidence request accepted under connection enablement; no second consent screen'
            ) 30
            Update-FabricConsentEvidence $fabricConsentEvidence $fabricLog
            $fabricGuiStage = Get-FabricGuiStage $fabricConsentEvidence $fabricGuiStage
            Wait-ServiceLog $fabricClient $fabricLog @(
                'MCAce evidence consent inherited from connection enablement'
            ) 30
            Update-FabricConsentEvidence $fabricConsentEvidence $fabricLog
            $fabricGuiStage = Get-FabricGuiStage $fabricConsentEvidence $fabricGuiStage
            Wait-ServiceLog $fabricClient $fabricLog @(
                'MCAce evidence transfer COMPLETE request='
            ) 60
            Update-FabricConsentEvidence $fabricConsentEvidence $fabricLog
            $fabricGuiStage = Get-FabricGuiStage $fabricConsentEvidence $fabricGuiStage
            if (-not (Test-FabricEvidenceCoverage $fabricConsentEvidence)) {
                throw 'Fabric evidence flow completed without its full requested/non-rendered/allowed/inherited/completed marker chain'
            }
            $evidenceAudit = Join-Path $velocityRoot 'plugins\mcace\evidence-audit.log'
            $auditDeadline = [DateTime]::UtcNow.AddSeconds(30)
            $auditLine = $null
            while ([DateTime]::UtcNow -lt $auditDeadline) {
                if (Test-Path -LiteralPath $evidenceAudit) {
                    $auditLine = Get-Content -LiteralPath $evidenceAudit -ErrorAction SilentlyContinue |
                        Where-Object { $_ -match '^COLLECT status=EVIDENCE_COLLECTION_COLLECTED ' -and
                            $_ -match 'caseId=platform-smoke-frame ' -and
                            $_ -match 'scope=GAME_RENDER_FRAME ' -and $_ -match 'size=[1-9][0-9]* ' } |
                        Select-Object -Last 1
                    if ($null -ne $auditLine) { break }
                }
                Start-Sleep -Seconds 1
            }
            if ($null -eq $auditLine) {
                throw 'Velocity did not write a content-free COMPLETE audit summary for the signed game-render-frame request'
            }
            $evidenceAuditSummaryObserved = $true
            if ($RetainDiagnostics) {
                Copy-Item -LiteralPath $evidenceAudit -Destination (Join-Path $runRoot 'velocity-evidence-audit.log')
            }
            $evidenceReport = [ordered]@{
                outcome = 'COMPLETE'
                request_scope = 'GAME_RENDER_FRAME'
                consent = 'single-visible-connection-enablement'
                raw_content_retained = $false
            }
        }
        if (-not $fabricClient.Process.WaitForExit(60000)) {
            $reason = if ($WithFabricEvidence) { 'evidence COMPLETE' } else { 'authentication result' }
            throw "Fabric client did not exit after $reason"
        }
        Stop-JavaService $fabricClient ''
        $fabricClient = $null
        if ($RetainDiagnostics) {
            Copy-Item -LiteralPath $fabricLog -Destination (Join-Path $runRoot 'fabric-client.log')
        }
        $fabricReport = [ordered]@{
            minecraft_version = [string]$fabricDescriptor.minecraft_version
            loader_version = '0.19.3'
            outcome = 'VERIFIED'
            risk_score = 0
            development_profile_observed = $true
            manual_consent_handshake_timeout_seconds = $manualConsentHandshakeTimeoutSeconds
            evidence = $evidenceReport
        }
    }
    if ($RetainDiagnostics) {
        Copy-Item -LiteralPath $paperLog -Destination (Join-Path $runRoot 'paper-positive.log')
    }

    Stop-JavaService $paper 'stop'
    $paper = $null
    if (Test-Path -LiteralPath $paperLog) { Remove-Item -LiteralPath $paperLog -Force }
    $paperPinBackup = "$paperPin.intentionally-absent"
    Move-Item -LiteralPath $paperPin -Destination $paperPinBackup
    $paper = Start-JavaService 'paper-negative' $paperRoot (Join-Path $paperRoot 'paper.jar') '1024m' @('--nogui')
    Wait-ServiceLog $paper $paperLog @(
        'missing pinned proxy public key:',
        'Done ('
    ) 180
    $negativePaperLogText = Get-Content -Raw -LiteralPath $paperLog
    $negativePinFailureObserved =
        (Test-TextContains $negativePaperLogText 'missing pinned proxy public key:') -or
        (Test-TextContains $negativePaperLogText 'MCAce requires the trusted proxy identity/server-public-key.txt')
    $negativePluginDisabled = Test-TextContains $negativePaperLogText 'Disabling MCAce'
    $negativeChannelMarkerAbsent = -not (Test-TextContains $negativePaperLogText 'MCAce signed proxy admission channel enabled')
    if (-not $negativePinFailureObserved -or -not $negativePluginDisabled -or -not $negativeChannelMarkerAbsent) {
        throw 'Paper missing-pin case did not prove MCAce disabled without admission channel enablement'
    }
    if ($RetainDiagnostics) {
        Copy-Item -LiteralPath $paperLog -Destination (Join-Path $runRoot 'paper-negative.log')
    }
    Stop-JavaService $paper 'stop'
    $paper = $null
    Move-Item -LiteralPath $paperPinBackup -Destination $paperPin
    $paperPinBackup = $null

    $assertions = @(
        'Velocity loaded MCAce and registered its Phase 2 handshake service.',
        'Velocity created a persistent Ed25519 root identity.',
        'Paper loaded MCAce only after receiving the explicit Velocity public-key pin.',
        'Paper reported the same pinned key fingerprint.',
        'Paper rejected MCAce plugin enablement when the Velocity public-key pin was intentionally absent.',
        'Both services reached their ready state on loopback-only ports.'
    )
    if ($WithFabricClient) {
        $assertions += @(
            'Fabric Loader initialized MCAce from the uniquely identified final JAR without a source-set fallback.',
            "A real Fabric $FabricTarget client connected through Velocity and completed the signed MCAce handshake.",
            'Paper accepted the root-signed VERIFIED snapshot for the live carrier player.',
            'The Fabric client exited after its configured smoke completion point.'
        )
    }
    if ($WithFabricEvidence) {
        $assertions += @(
            'A signed GAME_RENDER_FRAME request reached the real Fabric client after authentication.',
            'A human approved the visible, one-shot consent screen; the client uploaded Begin/Chunk/Commit and received COMPLETE.',
            'Velocity recorded a content-free COMPLETE audit summary; raw image retention remained disabled.',
            'The smoke uses no desktop, window, cursor, or operating-system screen-capture API.'
        )
    }
    $report = New-SanitizedReleaseReport `
        $fabricConsentEvidence `
        $WithFabricClient `
        $WithFabricEvidence `
        $fabricArtifactMarkerObserved `
        ($fabricArtifactMarkerObserved -and
            ($currentEvidenceBinding.fabric_runtime_artifact_sha256 -ceq
                $currentEvidenceBinding.fabric_artifact_sha256)) `
        $explicitFileFixturePresent `
        $evidenceAuditSummaryObserved `
        ($identityFingerprintBeforeRestart -eq $identityFingerprintAfterRestart) `
        $velocityTransportClassesPresent `
        $paperAdmissionChannelEnabled `
        $negativePinFailureObserved `
        $negativePluginDisabled `
        $negativeChannelMarkerAbsent `
        $RetainDiagnostics `
        $assertions.Count `
        $remainingOwnedProcessCount `
        $velocityPolicyTuple
    $reportPath = Join-Path $runRoot 'report.json'
    $passed = $true
} catch {
    $smokeFailure = $_
    Write-Error ("PLATFORM_LOAD_SMOKE_FAILURE|{0}|{1}" -f $_.Exception.Message, $_.ScriptStackTrace)
} finally {
    try {
        Stop-JavaService $fabricClient ''
    } catch {
        Write-Warning "Fabric client cleanup failed: $($_.Exception.Message)"
    }
    try {
        Stop-JavaService $paper 'stop'
    } catch {
        Write-Warning "Paper cleanup failed: $($_.Exception.Message)"
    }
    try {
        Stop-JavaService $velocity 'end'
    } catch {
        Write-Warning "Velocity cleanup failed: $($_.Exception.Message)"
    }
    try {
        Stop-RunTokenJavaProcesses $runToken
    } catch {
        Write-Warning "Run-token Java cleanup failed: $($_.Exception.Message)"
    }
    try {
        $remainingOwnedProcessCount = @(Get-RunTokenJavaProcesses $runToken).Count
    } catch {
        Write-Warning "Run-token Java residue enumeration failed: $($_.Exception.Message)"
        $remainingOwnedProcessCount = -1
    }
    if ($null -ne $paperPinBackup -and (Test-Path -LiteralPath $paperPinBackup) -and
            $null -ne $paperPin -and -not (Test-Path -LiteralPath $paperPin)) {
        Move-Item -LiteralPath $paperPinBackup -Destination $paperPin
    }
    try {
        if ($null -eq $runLocalRuntimeBinding) {
            throw 'PLATFORM_SMOKE_RUN_LOCAL_RUNTIME_PRESTART_BINDING_REQUIRED'
        }
        $runLocalAfterRun = Get-RunLocalRuntimeBinding
        Assert-RunLocalRuntimeBinding $runLocalAfterRun $currentEvidenceBinding
        Assert-BindingSnapshotUnchanged $runLocalRuntimeBinding $runLocalAfterRun
        $currentAfterRun = Get-CurrentEvidenceBinding
        Assert-BindingSnapshotUnchanged $preBuildInputSnapshot $currentAfterRun
        Assert-BindingSnapshotUnchanged $currentEvidenceBinding $currentAfterRun
    } catch {
        if ($null -eq $smokeFailure) { $smokeFailure = $_ }
        $passed = $false
        Write-Warning "Runtime/input closure verification failed: $($_.Exception.Message)"
    }
    $cleanupPortsFree = (Test-LoopbackPortFree $proxyPort) -and (Test-LoopbackPortFree $paperPort)
    $cleanupCompleted = $cleanupPortsFree -and $remainingOwnedProcessCount -eq 0
    Update-FabricConsentEvidence $fabricConsentEvidence $fabricLog
    $fabricGuiStage = Get-FabricGuiStage $fabricConsentEvidence $fabricGuiStage
    $runSucceeded = $null -eq $smokeFailure -and $passed -and $cleanupCompleted
    if (-not $runSucceeded) {
        $diagnosticError = if ($null -ne $smokeFailure) {
            $smokeFailure.Exception.Message
        } elseif (-not $cleanupCompleted) {
            'Platform smoke assertions passed, but cleanup did not complete.'
        } else {
            'Platform smoke did not reach its passing report boundary.'
        }
        $diagnosticError = ([string]$diagnosticError).Replace($runToken, '<redacted-run-token>')
        $failureReport = [ordered]@{
            schema = 2
            artifact_class = 'diagnostic-non-release'
            status = 'failed'
            release_evidence = $false
            diagnostics_retained = [bool]$RetainDiagnostics
            fabric_target = $FabricTarget
            minecraft_version = [string]$fabricDescriptor.minecraft_version
            fabric_api_version = [string]$fabricDescriptor.fabric_api_version
            fabric_artifact_kind = [string]$fabricDescriptor.artifact_kind
            fabric_java_major = [int]$fabricDescriptor.java_major
            fabric_runtime_mode = $fabricRuntimeMode
            fabric_runtime_jar_loaded = [bool]$fabricArtifactMarkerObserved
            fabric_release_jar_loaded = [bool]$fabricArtifactMarkerObserved
            fabric_artifact_marker_observed = [bool]$fabricArtifactMarkerObserved
            fabric_build_id = $fabricSmokeBuildId
            run_id = $runId
            completed_at = (Get-Date).ToUniversalTime().ToString('o')
            error = $diagnosticError
            run_root = $runRoot
            fabric_gui_stage = $fabricGuiStage
            explicit_file_fixture_present = $explicitFileFixturePresent
            explicit_file_manifest_entries = [int]$fabricConsentEvidence['explicit_file_manifest_entries']
            enablement_consent_requested = [bool]$fabricConsentEvidence['enablement_requested']
            enablement_consent_rendered = [bool]$fabricConsentEvidence['enablement_rendered']
            enablement_consent_accepted = [bool]$fabricConsentEvidence['enablement_accepted']
            explicit_file_consent_requested = [bool]$fabricConsentEvidence['explicit_file_requested']
            explicit_file_consent_rendered = [bool]$fabricConsentEvidence['explicit_file_rendered']
            explicit_file_consent_accepted = [bool]$fabricConsentEvidence['explicit_file_accepted']
            explicit_file_consent_screen_observed = [bool]$fabricConsentEvidence['explicit_file_rendered']
            fabric_authenticated = [bool]$fabricConsentEvidence['authenticated']
            game_render_frame_requested = [bool]$fabricConsentEvidence['game_render_frame_requested']
            game_render_frame_consent_rendered = [bool]$fabricConsentEvidence['game_render_frame_rendered']
            game_render_frame_consent_allowed = [bool]$fabricConsentEvidence['game_render_frame_allowed']
            game_render_frame_consent_inherited = [bool]$fabricConsentEvidence['game_render_frame_inherited']
            game_render_frame_completed = [bool]$fabricConsentEvidence['game_render_frame_completed']
            fabric_gui_coverage = ($WithFabricClient -and (Test-FabricGuiCoverage $fabricConsentEvidence))
            fabric_evidence_coverage = ($WithFabricEvidence -and (Test-FabricEvidenceCoverage $fabricConsentEvidence))
            manual_consent_handshake_timeout_seconds = if ($WithFabricClient) {
                $manualConsentHandshakeTimeoutSeconds
            } else { 0 }
            cleanup_completed = $cleanupCompleted
            cleanup_ports_free = $cleanupPortsFree
            remaining_owned_process_count = $remainingOwnedProcessCount
        }
        $reportPath = Join-Path $runRoot 'report.json'
        [System.IO.File]::WriteAllText(
            $reportPath, ($failureReport | ConvertTo-Json -Depth 6),
            [System.Text.UTF8Encoding]::new($false))
        if ($RetainDiagnostics) {
            Write-DiagnosticsNotice $runRoot 'Diagnostics from this failed run were retained because -RetainDiagnostics was explicitly supplied.'
        } else {
            Remove-UnretainedDiagnostics $runRoot $reportPath
        }
    } elseif ($null -ne $report) {
        $report['cleanup_completed'] = $cleanupCompleted
        $report['cleanup_ports_free'] = $cleanupPortsFree
        $report['remaining_owned_process_count'] = $remainingOwnedProcessCount
        $reportRaw = $report | ConvertTo-Json -Depth 6
        $reportBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($reportRaw)
        [System.IO.File]::WriteAllBytes($reportPath, $reportBytes)
        $bindingPath = Join-Path $runRoot 'binding.json'
        $binding = New-EvidenceBinding $reportBytes $report $currentEvidenceBinding
        [System.IO.File]::WriteAllText(
            $bindingPath, ($binding | ConvertTo-Json -Depth 4),
            [System.Text.UTF8Encoding]::new($false))
        $null = Assert-EvidencePair $reportPath $currentEvidenceBinding
        if ($RetainDiagnostics) {
            Write-DiagnosticsNotice $runRoot 'Diagnostics were retained because -RetainDiagnostics was explicitly supplied.'
        } else {
            Remove-UnretainedDiagnostics $runRoot $reportPath $bindingPath
        }
    }
}

if ($null -ne $smokeFailure -or -not $passed -or -not $cleanupCompleted) {
    throw 'MCAce platform load smoke did not complete cleanly; inspect report.json'
}
Write-Output "PLATFORM_LOAD_SMOKE_PASS|$runRoot"
