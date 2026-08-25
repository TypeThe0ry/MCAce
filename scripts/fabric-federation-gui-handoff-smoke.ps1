[CmdletBinding(DefaultParameterSetName = 'Disabled')]
param(
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [switch]$Execute,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [switch]$ReportOnly,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidateSet('1.21.11', '26.1.2', '26.2')]
    [string]$FabricTarget,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidateSet('VELOCITY', 'BUNGEE')]
    [string]$SourceProxy,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidateSet('VELOCITY', 'BUNGEE')]
    [string]$TargetProxy,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [switch]$EnablementHumanAttested,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedFabricArtifactSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedVelocityPluginSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedBungeePluginSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPaperPluginSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedVelocityServerSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedBungeeServerSha256,
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
    [Parameter(ParameterSetName = 'Execute')]
    [ValidateRange(60, 300)]
    [int]$FederationAssertionTtlSeconds = 120,
    [Parameter(ParameterSetName = 'Execute')]
    [ValidateRange(30, 180)]
    [int]$HumanTransitionTimeoutSeconds = 90,
    [ValidateRange(1, 1440)]
    [int]$MaximumReportAgeMinutes = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $Execute -and -not $ReportOnly) {
    throw 'FABRIC_FEDERATION_GUI_EXPLICIT_EXECUTE_OR_REPORT_ONLY_REQUIRED'
}
$SourceProxy = $SourceProxy.ToUpperInvariant()
$TargetProxy = $TargetProxy.ToUpperInvariant()

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$wrapperPath = [System.IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$wrapperTestPath = Join-Path $PSScriptRoot 'test-fabric-federation-gui-handoff-smoke.ps1'
$platformWrapperPath = Join-Path $PSScriptRoot 'platform-load-smoke.ps1'
$evidenceRoot = Join-Path $repoRoot 'build\fabric-federation-gui-handoff'
$evidenceRunsRoot = Join-Path $evidenceRoot 'evidence-runs'
$serverMatrixRoot = Join-Path $repoRoot 'build\runtime-assets'
$serverMatrixManifest = Join-Path $serverMatrixRoot 'manifest.json'
$serverPreparedManifest = Join-Path $serverMatrixRoot 'prepared-manifest.json'
$stagedModernDependencies = Join-Path $repoRoot 'build\fabric-modern-deps'
$velocityPlugin = Join-Path $repoRoot 'mcace-server-velocity\build\libs\mcace-server-velocity-0.1.0-SNAPSHOT.jar'
$bungeePlugin = Join-Path $repoRoot 'mcace-server-bungeecord\build\libs\mcace-server-bungeecord-0.1.0-SNAPSHOT.jar'
$paperPlugin = Join-Path $repoRoot 'mcace-server-paper\build\libs\mcace-server-paper-0.1.0-SNAPSHOT.jar'
$gradleVersion = '9.6.1'
$fabricArtifactVersion = '0.1.0-SNAPSHOT'
$reportSchema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V2'
$bindingSchema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V2'
$commitSchema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V2'
$artifactClass = 'sanitized-final-fabric-federation-gui-handoff'
$requiredHumanGuiMarkers = @(
    'MCAce enablement consent requested for signed policy',
    'MCAce enablement consent screen rendered',
    'MCAce enablement accepted for the current connection; no additional consent screens will be shown',
    'MCAce federation source export consent inherited from connection enablement',
    'MCAce federation target import consent inherited from connection enablement'
)

# The platform gate is the single target/JDK/cache/artifact authority. Import its exact
# function ASTs and descriptor assignment instead of maintaining a weaker second copy.
$platformTokens = $null
$platformErrors = $null
$platformAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $platformWrapperPath, [ref]$platformTokens, [ref]$platformErrors)
if (@($platformErrors).Count -ne 0) {
    throw 'FABRIC_FEDERATION_GUI_PLATFORM_WRAPPER_PARSE_FAILED'
}
$platformFunctionNames = @(
    'Assert-SmokeRunToken', 'New-SmokeRunToken', 'Test-ExactRunTokenArgument',
    'Get-Sha256', 'Get-Sha1', 'Get-ObjectProperty', 'Resolve-ServerMatrixAssets',
    'Assert-FabricAssetCache', 'Assert-DirectLocalPath', 'Initialize-SafeOwnedDirectory',
    'New-ExclusiveOwnedDirectory', 'Assert-OwnedTreeNoReparse', 'Get-VerifiedArtifact',
    'Get-FreeLoopbackPort', 'Test-LoopbackPortFree', 'Assert-LoopbackListener',
    'Set-ProcessArguments', 'Test-TextContains', 'Get-Sha256HexFromBytes',
    'Get-CompatibleRelativePath', 'Resolve-ExactJava', 'Resolve-RootJava21',
    'Resolve-TargetJava', 'Resolve-OfflineGradle961', 'Invoke-PinnedOfflineGradle',
    'Expand-VelocityConfiguration', 'Test-JarEntry', 'Get-FabricArtifactIdentity',
    'Assert-FabricArtifactMarker', 'Start-FabricClient', 'Get-SmokeProcessTreeTargets',
    'Stop-SmokeProcessTree', 'Get-RunTokenJavaProcesses', 'Stop-RunTokenJavaProcesses',
    'Stop-JavaService', 'Get-FabricDevelopmentPlayerName', 'Get-BytesSha256',
    'Get-ManifestSha256', 'Get-SourceManifestBinding', 'Assert-CanonicalPreparedRelative',
    'Get-PreparedTreeBinding', 'Get-PreparedPaperBinding', 'Get-JsonPropertyNames',
    'Test-ExactJsonProperties', 'Test-JsonInteger'
)
$platformFunctions = @($platformAst.FindAll({
    param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $true))
foreach ($functionName in $platformFunctionNames) {
    $matches = @($platformFunctions | Where-Object Name -CEQ $functionName)
    if ($matches.Count -ne 1) {
        throw "FABRIC_FEDERATION_GUI_PLATFORM_FUNCTION_CONTRACT_INVALID: $functionName"
    }
    Invoke-Expression $matches[0].Extent.Text
}
$targetAssignments = @($platformAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$fabricTargets'
}, $true))
if ($targetAssignments.Count -ne 1) {
    throw 'FABRIC_FEDERATION_GUI_PLATFORM_TARGET_DESCRIPTOR_CONTRACT_INVALID'
}
$fabricTargets = Invoke-Expression $targetAssignments[0].Right.Extent.Text
if (@($fabricTargets.Keys).Count -ne 3 -or
        ((@($fabricTargets.Keys) -join ',') -cne '1.21.11,26.1.2,26.2')) {
    throw 'FABRIC_FEDERATION_GUI_PLATFORM_TARGET_SET_INVALID'
}
$fabricDescriptor = $fabricTargets[$FabricTarget]
if ($null -eq $fabricDescriptor) {
    throw 'FABRIC_FEDERATION_GUI_FABRIC_TARGET_INVALID'
}
$fabricRuntimeMode = [string]$fabricDescriptor.runtime_mode
$fabricArtifactJar = [string]$fabricDescriptor.artifact_path
$preparedPaperRoot = ''
$velocityArtifact = [ordered]@{
    Name = 'velocity-3.5.1-615.jar'
    Url = 'https://fill-data.papermc.io/v1/objects/b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3/velocity-3.5.1-615.jar'
    Sha256 = 'b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3'
}

function ConvertFrom-StrictJson([string]$Raw) {
    $trimmed = $Raw.Trim()
    if ($trimmed.Length -lt 2 -or $trimmed[0] -cne '{' -or
            $trimmed[$trimmed.Length - 1] -cne '}') {
        throw 'FABRIC_FEDERATION_GUI_JSON_TOP_LEVEL_OBJECT_REQUIRED'
    }
    $command = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
    if ($command.Parameters.ContainsKey('DateKind')) {
        $value = ConvertFrom-Json -InputObject $Raw -DateKind String -ErrorAction Stop
    } else {
        $value = ConvertFrom-Json -InputObject $Raw -ErrorAction Stop
    }
    # All V2 evidence documents are deliberately flat scalar objects. Count raw property tokens
    # against the converted top-level object and reject case-insensitive duplicates so PowerShell's
    # object adapter cannot collapse duplicate JSON names into an apparently valid schema.
    $propertyMatches = [regex]::Matches(
        $Raw, '"(?<name>[^"\r\n]+)"\s*:',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $properties = @($value.PSObject.Properties)
    if ($propertyMatches.Count -ne $properties.Count) {
        throw 'FABRIC_FEDERATION_GUI_JSON_FLAT_UNIQUE_PROPERTIES_REQUIRED'
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($match in $propertyMatches) {
        if (-not $seen.Add($match.Groups['name'].Value)) {
            throw 'FABRIC_FEDERATION_GUI_JSON_FLAT_UNIQUE_PROPERTIES_REQUIRED'
        }
    }
    return $value
}

function Assert-SanitizedJson([string]$Raw) {
    if ($Raw.Length -gt 65536 -or
            $Raw -match '(?i)[A-Z]:[\\/]|\\\\|(?:^|["\s])/(?:home|users|tmp|var|opt|mnt|root)/' -or
            $Raw -match '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b' -or
            $Raw -match '(?i)private.?key|client.?secret|access.?token|raw.?grant|raw.?presentation') {
        throw 'FABRIC_FEDERATION_GUI_EVIDENCE_NOT_SANITIZED'
    }
}

function Open-LockedEvidence([string]$Path) {
    $resolved = Assert-DirectLocalPath $Path
    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $resolved, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read)
        if ($stream.Length -le 0L -or $stream.Length -gt 65536L) {
            throw 'FABRIC_FEDERATION_GUI_EVIDENCE_SIZE_INVALID'
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

function Test-JsonString([object]$Value) { return $Value -is [string] }
function Test-JsonBoolean([object]$Value) { return $Value -is [bool] }

function Resolve-FederationServerAssets {
    $platformAssets = Resolve-ServerMatrixAssets
    $manifestPath = Assert-DirectLocalPath $serverMatrixManifest
    try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'FABRIC_FEDERATION_GUI_SERVER_MATRIX_MANIFEST_INVALID' }
    if ($manifest.schema -cne 'MCACE_SERVER_VERSION_MATRIX_ASSETS_V1' -or
            @($manifest.assets).Count -ne 8) {
        throw 'FABRIC_FEDERATION_GUI_SERVER_MATRIX_MANIFEST_INVALID'
    }
    $bungee = @($manifest.assets | Where-Object {
        $_.project -ceq 'bungeecord' -and $_.version -ceq '2085' -and $_.build -ceq '2085'
    })
    if ($bungee.Count -ne 1 -or
            [string]$bungee[0].url -cne 'https://hub.spigotmc.org/jenkins/job/BungeeCord/2085/artifact/bootstrap/target/BungeeCord.jar' -or
            [string]$bungee[0].sha256 -cne 'e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce' -or
            [long]$bungee[0].size -ne 25599274L -or [string]$bungee[0].channel -cne 'REVIEWED' -or
            [int]$bungee[0].java_major -ne 21 -or
            ((@($bungee[0].target_versions) -join ',') -cne '1.21.11,26.1.2,26.2')) {
        throw 'FABRIC_FEDERATION_GUI_REVIEWED_BUNGEE_IDENTITY_INVALID'
    }
    return [pscustomobject]@{
        manifest_path = $platformAssets.manifest_path
        manifest_sha256 = $platformAssets.manifest_sha256
        velocity = $platformAssets.velocity
        paper = $platformAssets.paper
        prepared_root = $platformAssets.prepared_root
        bungee = [ordered]@{
            Name = 'bungeecord-2085.jar'
            Url = [string]$bungee[0].url
            Sha256 = [string]$bungee[0].sha256
            Size = [long]$bungee[0].size
            Path = Join-Path $serverMatrixRoot 'bungeecord\2085\server.jar'
        }
    }
}

function Get-VerifiedBungeeArtifact([System.Collections.IDictionary]$Artifact) {
    if ($Artifact.Url -cne 'https://hub.spigotmc.org/jenkins/job/BungeeCord/2085/artifact/bootstrap/target/BungeeCord.jar' -or
            $Artifact.Sha256 -cne 'e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce' -or
            [long]$Artifact.Size -ne 25599274L) {
        throw 'FABRIC_FEDERATION_GUI_BUNGEE_DECLARATION_INVALID'
    }
    $path = Assert-DirectLocalPath ([string]$Artifact.Path)
    if ((Get-Item -LiteralPath $path).Length -ne [long]$Artifact.Size -or
            (Get-Sha256 $path) -cne [string]$Artifact.Sha256) {
        throw 'FABRIC_FEDERATION_GUI_BUNGEE_CACHE_INVALID'
    }
    return $path
}

function Get-ImmutableInputBinding {
    $currentWrapper = Get-Sha256 (Assert-DirectLocalPath $wrapperPath)
    $currentPlatform = Get-Sha256 (Assert-DirectLocalPath $platformWrapperPath)
    $rootJava = Resolve-RootJava21
    $targetJava = Resolve-TargetJava
    $gradle = Resolve-OfflineGradle961
    $assets = Resolve-FederationServerAssets
    if ([string]$assets.prepared_root -cne $preparedPaperRoot) {
        throw 'FABRIC_FEDERATION_GUI_PREPARED_TARGET_CHANGED'
    }
    $velocityServer = Get-VerifiedArtifact $assets.velocity
    $bungeeServer = Get-VerifiedBungeeArtifact $assets.bungee
    $paperServer = Get-VerifiedArtifact $assets.paper
    $source = Get-SourceManifestBinding
    $prepared = Get-PreparedPaperBinding
    $fabricAssets = Assert-FabricAssetCache $true
    return [ordered]@{
        wrapper_sha256 = $currentWrapper
        wrapper_test_sha256 = Get-Sha256 (Assert-DirectLocalPath $wrapperTestPath)
        platform_wrapper_sha256 = $currentPlatform
        source_manifest_sha256 = $source.sha256
        source_file_count = [int]$source.file_count
        fabric_target = $FabricTarget
        minecraft_version = [string]$fabricDescriptor.minecraft_version
        fabric_api_version = [string]$fabricDescriptor.fabric_api_version
        fabric_artifact_kind = [string]$fabricDescriptor.artifact_kind
        fabric_java_major = [int]$fabricDescriptor.java_major
        fabric_runtime_mode = $fabricRuntimeMode
        server_matrix_manifest_sha256 = [string]$assets.manifest_sha256
        velocity_server_sha256 = Get-Sha256 $velocityServer
        bungee_server_sha256 = Get-Sha256 $bungeeServer
        paper_server_sha256 = Get-Sha256 $paperServer
        paper_prepared_manifest_sha256 = $prepared.manifest_sha256
        paper_prepared_tree_sha256 = $prepared.tree_sha256
        paper_prepared_file_count = [int]$prepared.file_count
        paper_prepared_total_size = [long]$prepared.total_size
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

function Get-CurrentBinding {
    $current = Get-ImmutableInputBinding
    foreach ($artifact in @($fabricArtifactJar, $velocityPlugin, $bungeePlugin, $paperPlugin)) {
        $null = Assert-DirectLocalPath $artifact
    }
    $identity = Get-FabricArtifactIdentity $fabricArtifactJar $fabricDescriptor
    $current['fabric_artifact_sha256'] = Get-Sha256 $fabricArtifactJar
    $current['fabric_build_id'] = $identity.build_id
    $current['velocity_plugin_sha256'] = Get-Sha256 $velocityPlugin
    $current['bungee_plugin_sha256'] = Get-Sha256 $bungeePlugin
    $current['paper_plugin_sha256'] = Get-Sha256 $paperPlugin
    return $current
}

function Assert-BindingUnchanged(
        [System.Collections.IDictionary]$Before,
        [System.Collections.IDictionary]$After,
        [string]$FailureCode) {
    if ($Before.Count -ne $After.Count) { throw $FailureCode }
    foreach ($name in @($Before.Keys)) {
        if (-not $After.Contains($name) -or [string]$Before[$name] -cne [string]$After[$name]) {
            throw "$FailureCode`: $name"
        }
    }
}

function Assert-ReportOnlyExpectedBinding([System.Collections.IDictionary]$Current) {
    $expected = [ordered]@{
        fabric_artifact_sha256 = $ExpectedFabricArtifactSha256.ToLowerInvariant()
        velocity_plugin_sha256 = $ExpectedVelocityPluginSha256.ToLowerInvariant()
        bungee_plugin_sha256 = $ExpectedBungeePluginSha256.ToLowerInvariant()
        paper_plugin_sha256 = $ExpectedPaperPluginSha256.ToLowerInvariant()
        velocity_server_sha256 = $ExpectedVelocityServerSha256.ToLowerInvariant()
        bungee_server_sha256 = $ExpectedBungeeServerSha256.ToLowerInvariant()
        paper_server_sha256 = $ExpectedPaperServerSha256.ToLowerInvariant()
        paper_prepared_manifest_sha256 = $ExpectedPaperPreparedManifestSha256.ToLowerInvariant()
        paper_prepared_tree_sha256 = $ExpectedPaperPreparedTreeSha256.ToLowerInvariant()
        fabric_version_info_sha256 = $ExpectedFabricVersionInfoSha256.ToLowerInvariant()
        fabric_asset_index_sha256 = $ExpectedFabricAssetIndexSha256.ToLowerInvariant()
        fabric_asset_object_manifest_sha256 = $ExpectedFabricAssetObjectManifestSha256.ToLowerInvariant()
    }
    foreach ($entry in $expected.GetEnumerator()) {
        if ([string]$Current[$entry.Key] -cne [string]$entry.Value) {
            throw "FABRIC_FEDERATION_GUI_REPORT_ONLY_EXPECTED_HASH_MISMATCH: $($entry.Key)"
        }
    }
}

$reportPropertyNames = @(
    'schema', 'generated_at', 'source_mode', 'status', 'artifact_class',
    'fabric_target', 'minecraft_version', 'fabric_api_version', 'fabric_artifact_kind',
    'fabric_java_major', 'fabric_runtime_mode', 'fabric_build_id',
    'fabric_codesource_sha256_observed', 'source_proxy', 'target_proxy',
    'federation_assertion_ttl_seconds', 'operator_human_attestation_count',
    'human_visible_federation_consent_count', 'no_gui_automation',
    'raw_peer_evidence_used', 'raw_content_retained', 'fabric_artifact_mode_verified',
    'source_local_auth_verified', 'source_paper_admission_verified',
    'enablement_consent_requested', 'enablement_consent_rendered',
    'enablement_consent_accepted', 'source_export_consent_inherited',
    'source_grant_stored_memory_only', 'source_grant_ready_observed',
    'source_disconnected_before_target_auth', 'target_local_auth_verified',
    'target_import_consent_inherited',
    'presentation_sent', 'target_observation_recorded', 'target_subject_bound',
    'target_observation_status_count_one', 'target_observation_status_one_before_expiry',
    'target_paper_admission_verified', 'local_trust_risk_admission_unchanged',
    'target_session_connected_through_expiry', 'observation_expired',
    'target_observation_status_zero_after_expiry', 'client_shutdown_completed',
    'cleanup_ports_free', 'remaining_owned_process_count', 'passed'
)

function Assert-PassingReportRaw(
        [string]$Raw,
        [System.Collections.IDictionary]$Current,
        [string]$ExpectedSource,
        [string]$ExpectedTarget) {
    try { $report = ConvertFrom-StrictJson $Raw }
    catch { throw 'FABRIC_FEDERATION_GUI_REPORT_JSON_INVALID' }
    if (-not (Test-ExactJsonProperties $report $reportPropertyNames)) {
        throw 'FABRIC_FEDERATION_GUI_REPORT_SCHEMA_INVALID'
    }
    foreach ($name in @(
            'schema', 'generated_at', 'source_mode', 'status', 'artifact_class',
            'fabric_target', 'minecraft_version', 'fabric_api_version', 'fabric_artifact_kind',
            'fabric_runtime_mode', 'fabric_build_id', 'fabric_codesource_sha256_observed',
            'source_proxy', 'target_proxy')) {
        if (-not (Test-JsonString $report.$name)) {
            throw "FABRIC_FEDERATION_GUI_REPORT_TYPE_INVALID: $name"
        }
    }
    foreach ($name in @(
            'no_gui_automation', 'raw_peer_evidence_used', 'raw_content_retained',
            'fabric_artifact_mode_verified', 'source_local_auth_verified',
            'source_paper_admission_verified', 'enablement_consent_requested',
            'enablement_consent_rendered', 'enablement_consent_accepted',
            'source_export_consent_inherited', 'source_grant_stored_memory_only',
            'source_grant_ready_observed', 'source_disconnected_before_target_auth',
            'target_local_auth_verified', 'target_import_consent_inherited',
            'presentation_sent',
            'target_observation_recorded', 'target_subject_bound',
            'target_observation_status_count_one', 'target_observation_status_one_before_expiry',
            'target_paper_admission_verified', 'local_trust_risk_admission_unchanged',
            'target_session_connected_through_expiry', 'observation_expired',
            'target_observation_status_zero_after_expiry',
            'client_shutdown_completed', 'cleanup_ports_free', 'passed')) {
        if (-not (Test-JsonBoolean $report.$name)) {
            throw "FABRIC_FEDERATION_GUI_REPORT_TYPE_INVALID: $name"
        }
    }
    foreach ($name in @(
            'fabric_java_major', 'federation_assertion_ttl_seconds',
            'operator_human_attestation_count', 'human_visible_federation_consent_count',
            'remaining_owned_process_count')) {
        if (-not (Test-JsonInteger $report.$name)) {
            throw "FABRIC_FEDERATION_GUI_REPORT_INTEGER_TYPE_INVALID: $name"
        }
    }
    $timestamp = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            [string]$report.generated_at, 'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None, [ref]$timestamp)) {
        throw 'FABRIC_FEDERATION_GUI_REPORT_TIMESTAMP_INVALID'
    }
    $age = [DateTimeOffset]::UtcNow - $timestamp
    if ($age.TotalMinutes -lt 0 -or $age.TotalMinutes -gt $MaximumReportAgeMinutes) {
        throw 'FABRIC_FEDERATION_GUI_REPORT_STALE'
    }
    $requiredTrue = @(
        'no_gui_automation', 'fabric_artifact_mode_verified', 'source_local_auth_verified',
        'source_paper_admission_verified', 'enablement_consent_requested',
        'enablement_consent_rendered', 'enablement_consent_accepted',
        'source_export_consent_inherited', 'source_grant_stored_memory_only',
        'source_grant_ready_observed', 'source_disconnected_before_target_auth',
        'target_local_auth_verified', 'target_import_consent_inherited',
        'presentation_sent',
        'target_observation_recorded', 'target_subject_bound',
        'target_observation_status_count_one', 'target_observation_status_one_before_expiry',
        'target_paper_admission_verified', 'local_trust_risk_admission_unchanged',
        'target_session_connected_through_expiry', 'observation_expired',
        'target_observation_status_zero_after_expiry',
        'client_shutdown_completed', 'cleanup_ports_free', 'passed'
    )
    foreach ($name in $requiredTrue) {
        if (-not [bool]$report.$name) {
            throw "FABRIC_FEDERATION_GUI_REQUIRED_ASSERTION_FALSE: $name"
        }
    }
    if ($report.schema -cne $reportSchema -or
            $report.source_mode -cne 'EXECUTED_REAL_FABRIC_GUI' -or
            $report.status -cne 'passed' -or $report.artifact_class -cne $artifactClass -or
            $report.fabric_target -cne $FabricTarget -or
            $report.minecraft_version -cne [string]$fabricDescriptor.minecraft_version -or
            $report.fabric_api_version -cne [string]$fabricDescriptor.fabric_api_version -or
            $report.fabric_artifact_kind -cne [string]$fabricDescriptor.artifact_kind -or
            [int]$report.fabric_java_major -ne [int]$fabricDescriptor.java_major -or
            $report.fabric_runtime_mode -cne [string]$fabricDescriptor.runtime_mode -or
            $report.fabric_build_id -cne [string]$Current.fabric_build_id -or
            $report.fabric_codesource_sha256_observed -cne [string]$Current.fabric_artifact_sha256 -or
            $report.source_proxy -cne $ExpectedSource -or $report.target_proxy -cne $ExpectedTarget -or
            [int]$report.federation_assertion_ttl_seconds -lt 60 -or
            [int]$report.federation_assertion_ttl_seconds -gt 300 -or
            [int]$report.operator_human_attestation_count -ne 1 -or
            [int]$report.human_visible_federation_consent_count -ne 1 -or
            [bool]$report.raw_peer_evidence_used -or [bool]$report.raw_content_retained -or
            [int]$report.remaining_owned_process_count -ne 0) {
        throw 'FABRIC_FEDERATION_GUI_REPORT_INVALID'
    }
    return $report
}

function Assert-BindingRaw(
        [string]$Raw,
        [string]$ReportSha256,
        [object]$Report,
        [System.Collections.IDictionary]$Current) {
    try { $binding = ConvertFrom-StrictJson $Raw }
    catch { throw 'FABRIC_FEDERATION_GUI_BINDING_JSON_INVALID' }
    $names = @(
        'schema', 'report_schema', 'report_generated_at', 'report_sha256',
        'source_mode', 'source_proxy', 'target_proxy', 'passed'
    ) + @($Current.Keys)
    if (-not (Test-ExactJsonProperties $binding $names)) {
        throw 'FABRIC_FEDERATION_GUI_BINDING_SCHEMA_INVALID'
    }
    foreach ($name in @('schema', 'report_schema', 'report_generated_at', 'report_sha256',
            'source_mode', 'source_proxy', 'target_proxy')) {
        if (-not (Test-JsonString $binding.$name)) {
            throw "FABRIC_FEDERATION_GUI_BINDING_TYPE_INVALID: $name"
        }
    }
    if ($binding.schema -cne $bindingSchema -or $binding.report_schema -cne $reportSchema -or
            $binding.report_generated_at -cne $Report.generated_at -or
            $binding.report_sha256 -cne $ReportSha256 -or
            $binding.source_mode -cne 'EXECUTED_REAL_FABRIC_GUI' -or
            $binding.source_proxy -cne $Report.source_proxy -or
            $binding.target_proxy -cne $Report.target_proxy -or
            -not (Test-JsonBoolean $binding.passed) -or -not [bool]$binding.passed) {
        throw 'FABRIC_FEDERATION_GUI_BINDING_INVALID'
    }
    foreach ($name in @($Current.Keys)) {
        $expected = $Current[$name]
        $actual = $binding.$name
        if ($expected -is [bool]) {
            if (-not (Test-JsonBoolean $actual) -or [bool]$actual -ne [bool]$expected) {
                throw "FABRIC_FEDERATION_GUI_BINDING_CURRENT_MISMATCH: $name"
            }
        } elseif ($expected -is [byte] -or $expected -is [int16] -or
                $expected -is [int32] -or $expected -is [int64]) {
            if (-not (Test-JsonInteger $actual) -or [long]$actual -ne [long]$expected) {
                throw "FABRIC_FEDERATION_GUI_BINDING_CURRENT_MISMATCH: $name"
            }
        } elseif (-not (Test-JsonString $actual) -or [string]$actual -cne [string]$expected) {
            throw "FABRIC_FEDERATION_GUI_BINDING_CURRENT_MISMATCH: $name"
        }
    }
    return $binding
}

function Assert-CommitRaw(
        [string]$Raw,
        [string]$ReportSha256,
        [string]$BindingSha256,
        [object]$Report) {
    try { $commit = ConvertFrom-StrictJson $Raw }
    catch { throw 'FABRIC_FEDERATION_GUI_COMMIT_JSON_INVALID' }
    $names = @(
        'schema', 'report_schema', 'binding_schema', 'generated_at', 'report_sha256',
        'binding_sha256', 'fabric_target', 'source_proxy', 'target_proxy', 'passed'
    )
    if (-not (Test-ExactJsonProperties $commit $names)) {
        throw 'FABRIC_FEDERATION_GUI_COMMIT_SCHEMA_INVALID'
    }
    foreach ($name in @('schema', 'report_schema', 'binding_schema', 'generated_at',
            'report_sha256', 'binding_sha256', 'fabric_target', 'source_proxy', 'target_proxy')) {
        if (-not (Test-JsonString $commit.$name)) {
            throw "FABRIC_FEDERATION_GUI_COMMIT_TYPE_INVALID: $name"
        }
    }
    if (
            $commit.schema -cne $commitSchema -or $commit.report_schema -cne $reportSchema -or
            $commit.binding_schema -cne $bindingSchema -or
            $commit.generated_at -cne $Report.generated_at -or
            $commit.report_sha256 -cne $ReportSha256 -or
            $commit.binding_sha256 -cne $BindingSha256 -or
            $commit.fabric_target -cne $Report.fabric_target -or
            $commit.source_proxy -cne $Report.source_proxy -or
            $commit.target_proxy -cne $Report.target_proxy -or
            -not (Test-JsonBoolean $commit.passed) -or -not [bool]$commit.passed) {
        throw 'FABRIC_FEDERATION_GUI_COMMIT_INVALID'
    }
    return $commit
}

function Assert-EvidenceTriplet(
        [string]$ReportPath,
        [System.Collections.IDictionary]$Current,
        [string]$ExpectedSource,
        [string]$ExpectedTarget) {
    $reportEvidence = $null
    $bindingEvidence = $null
    $commitEvidence = $null
    try {
        $directory = Split-Path -Parent $ReportPath
        $reportEvidence = Open-LockedEvidence $ReportPath
        $bindingEvidence = Open-LockedEvidence (Join-Path $directory 'binding.json')
        $commitEvidence = Open-LockedEvidence (Join-Path $directory 'commit.json')
        $report = Assert-PassingReportRaw $reportEvidence.raw $Current $ExpectedSource $ExpectedTarget
        $null = Assert-BindingRaw $bindingEvidence.raw $reportEvidence.sha256 $report $Current
        $null = Assert-CommitRaw $commitEvidence.raw $reportEvidence.sha256 $bindingEvidence.sha256 $report
        return $report
    } finally {
        if ($null -ne $commitEvidence) { $commitEvidence.stream.Dispose() }
        if ($null -ne $bindingEvidence) { $bindingEvidence.stream.Dispose() }
        if ($null -ne $reportEvidence) { $reportEvidence.stream.Dispose() }
    }
}

function Get-LatestCompleteEvidenceReport {
    if (-not (Test-Path -LiteralPath $evidenceRunsRoot -PathType Container)) { return $null }
    $root = Assert-DirectLocalPath $evidenceRunsRoot -Directory
    $targetLeaf = $FabricTarget.Replace('.', '_')
    $leafPattern = '^[0-9]{8}T[0-9]{9}Z-{0}-{1}-to-{2}-[0-9a-f]{{32}}$' -f
        [regex]::Escape($targetLeaf), [regex]::Escape($SourceProxy), [regex]::Escape($TargetProxy)
    $candidate = Get-ChildItem -LiteralPath $root -Directory -Force |
        Where-Object {
            $_.Name -cmatch $leafPattern -and
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'report.json') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'binding.json') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'commit.json') -PathType Leaf)
        } | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if ($null -eq $candidate) { return $null }
    return Join-Path $candidate.FullName 'report.json'
}

function Write-NewUtf8File([string]$Path, [string]$Content) {
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Content)
    $stream = [System.IO.File]::Open(
        $Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    return $bytes
}

function Write-EvidenceTriplet(
        [string]$RunDirectory,
        [System.Collections.IDictionary]$Report,
        [System.Collections.IDictionary]$Current) {
    $reportPath = Join-Path $RunDirectory 'report.json'
    $bindingPath = Join-Path $RunDirectory 'binding.json'
    $commitPath = Join-Path $RunDirectory 'commit.json'
    $reportBytes = Write-NewUtf8File $reportPath ($Report | ConvertTo-Json -Depth 6 -Compress)
    $reportSha = Get-BytesSha256 $reportBytes
    $binding = [ordered]@{
        schema = $bindingSchema
        report_schema = $reportSchema
        report_generated_at = [string]$Report.generated_at
        report_sha256 = $reportSha
        source_mode = 'EXECUTED_REAL_FABRIC_GUI'
        source_proxy = $SourceProxy
        target_proxy = $TargetProxy
        passed = $true
    }
    foreach ($name in @($Current.Keys)) { $binding[$name] = $Current[$name] }
    $bindingBytes = Write-NewUtf8File $bindingPath ($binding | ConvertTo-Json -Depth 6 -Compress)
    $bindingSha = Get-BytesSha256 $bindingBytes
    $commit = [ordered]@{
        schema = $commitSchema
        report_schema = $reportSchema
        binding_schema = $bindingSchema
        generated_at = [string]$Report.generated_at
        report_sha256 = $reportSha
        binding_sha256 = $bindingSha
        fabric_target = $FabricTarget
        source_proxy = $SourceProxy
        target_proxy = $TargetProxy
        passed = $true
    }
    $null = Write-NewUtf8File $commitPath ($commit | ConvertTo-Json -Depth 4 -Compress)
    $null = Assert-EvidenceTriplet $reportPath $Current $SourceProxy $TargetProxy
    return $reportPath
}

function Start-FederationJavaService(
        [string]$Name,
        [string]$WorkingDirectory,
        [string]$Jar,
        [string]$MaximumHeap,
        [string[]]$ExtraArguments) {
    Assert-SmokeRunToken $runToken
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $script:TargetJavaPath
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    Set-ProcessArguments $startInfo `
        (@($runTokenJvmArgument, '-Xms128m', "-Xmx$MaximumHeap", '-jar', $Jar) + $ExtraArguments)
    $stdoutPath = Join-Path $WorkingDirectory "$Name-stdout.log"
    $stderrPath = Join-Path $WorkingDirectory "$Name-stderr.log"
    $stdoutStream = [System.IO.File]::Open(
        $stdoutPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read)
    $stderrStream = [System.IO.File]::Open(
        $stderrPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read)
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw "FABRIC_FEDERATION_GUI_SERVICE_START_FAILED: $Name" }
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdoutStream)
        $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderrStream)
        return [pscustomobject]@{
            Name = $Name
            Process = $process
            Pid = [int]$process.Id
            WorkingDirectory = $WorkingDirectory
            RunToken = $runToken
            StdoutPath = $stdoutPath
            StderrPath = $stderrPath
            StdoutStream = $stdoutStream
            StderrStream = $stderrStream
            StdoutTask = $stdoutTask
            StderrTask = $stderrTask
        }
    } catch {
        $stdoutStream.Dispose()
        $stderrStream.Dispose()
        $process.Dispose()
        throw
    }
}

function Send-ServiceCommand($Service, [string]$Command) {
    if ($null -eq $Service -or $Service.Process.HasExited) {
        throw 'FABRIC_FEDERATION_GUI_SERVICE_COMMAND_TARGET_EXITED'
    }
    $Service.Process.StandardInput.WriteLine($Command)
    $Service.Process.StandardInput.Flush()
}

function Get-ServiceText($Service) {
    if ($null -eq $Service) { return '' }
    $paths = [System.Collections.Generic.List[string]]::new()
    $paths.Add([string]$Service.StdoutPath)
    $paths.Add([string]$Service.StderrPath)
    foreach ($file in @(Get-ChildItem -LiteralPath $Service.WorkingDirectory -File -Filter 'proxy.log.*' -ErrorAction SilentlyContinue)) {
        $paths.Add($file.FullName)
    }
    $latest = Join-Path $Service.WorkingDirectory 'logs\latest.log'
    if (Test-Path -LiteralPath $latest -PathType Leaf) { $paths.Add($latest) }
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($path in @($paths.ToArray() | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $content = Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue
            if ($null -ne $content) { $parts.Add([string]$content) }
        }
    }
    return $parts -join [Environment]::NewLine
}

function Wait-ServiceRegex($Service, [string]$Pattern, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $content = Get-ServiceText $Service
        if ([regex]::IsMatch($content, $Pattern,
                [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)) { return }
        if ($Service.Process.HasExited) {
            throw "FABRIC_FEDERATION_GUI_SERVICE_EXITED_BEFORE_MARKER: $($Service.Name)"
        }
        Start-Sleep -Seconds 1
    }
    throw "FABRIC_FEDERATION_GUI_SERVICE_MARKER_TIMEOUT: $($Service.Name)"
}

function Get-ServiceRegexCount($Service, [string]$Pattern) {
    return [regex]::Matches(
        (Get-ServiceText $Service), $Pattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
}

function Wait-NewServiceRegex(
        $Service,
        [string]$Pattern,
        [int]$BaselineCount,
        [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Get-ServiceRegexCount $Service $Pattern) -gt $BaselineCount) { return }
        if ($Service.Process.HasExited) {
            throw "FABRIC_FEDERATION_GUI_SERVICE_EXITED_BEFORE_NEW_MARKER: $($Service.Name)"
        }
        Start-Sleep -Seconds 1
    }
    throw "FABRIC_FEDERATION_GUI_NEW_SERVICE_MARKER_TIMEOUT: $($Service.Name)"
}

function Get-SecondsUntilDeadline(
        [DateTimeOffset]$Deadline,
        [int]$MaximumSeconds,
        [string]$ExpiredError) {
    $remaining = [int][Math]::Floor(($Deadline - [DateTimeOffset]::UtcNow).TotalSeconds)
    if ($remaining -lt 1) { throw $ExpiredError }
    return [Math]::Min($MaximumSeconds, $remaining)
}

function Assert-NewPaperVerifiedSnapshot(
        $PaperService,
        [string]$PaperLogPath,
        [string]$PlayerName,
        [int]$TimeoutSeconds) {
    $pattern = 'MCAce: {0} trust=VERIFIED admission=VERIFIED risk=0 band=NORMAL' -f
        [regex]::Escape($PlayerName)
    $baseline = Get-FileRegexCount $PaperLogPath $pattern
    Send-ServiceCommand $PaperService "mcace check $PlayerName"
    Wait-NewFileRegex $PaperService $PaperLogPath $pattern $baseline $TimeoutSeconds
}

function Assert-TargetSessionStillConnected(
        $FabricClient,
        $TargetProxyService,
        $TargetPaperService,
        [string]$TargetPaperLog,
        [string]$DisconnectMarker,
        [int]$DisconnectBaseline) {
    if ($FabricClient.Process.HasExited -or $TargetProxyService.Process.HasExited -or
            $TargetPaperService.Process.HasExited) {
        throw 'FABRIC_FEDERATION_GUI_TARGET_RUNTIME_EXITED_BEFORE_OBSERVATION_EXPIRY'
    }
    if ((Get-FileLiteralCount $TargetPaperLog $DisconnectMarker) -ne $DisconnectBaseline) {
        throw 'FABRIC_FEDERATION_GUI_TARGET_SESSION_DISCONNECTED_BEFORE_OBSERVATION_EXPIRY'
    }
}

function Stop-FederationJavaService($Service, [string]$Command) {
    if ($null -eq $Service) { return }
    $process = $Service.Process
    $rootPid = [int]$Service.Pid
    try {
        if (-not $process.HasExited) {
            if (-not [string]::IsNullOrWhiteSpace($Command)) {
                try { Send-ServiceCommand $Service $Command } catch { }
            }
            if (-not $process.WaitForExit(30000)) {
                Stop-SmokeProcessTree $rootPid $Service.RunToken
                if (-not $process.HasExited) {
                    $process.Kill()
                    [void]$process.WaitForExit(10000)
                }
            }
        }
        Stop-SmokeProcessTree $rootPid $Service.RunToken
        $Service.StdoutTask.GetAwaiter().GetResult()
        $Service.StderrTask.GetAwaiter().GetResult()
    } finally {
        $Service.StdoutStream.Flush()
        $Service.StderrStream.Flush()
        $Service.StdoutStream.Dispose()
        $Service.StderrStream.Dispose()
        $process.Dispose()
    }
}

function Write-Utf8([string]$Path, [string]$Content) {
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function Set-ExactConfigProperties(
        [string]$Path,
        [System.Collections.IDictionary]$Values) {
    $resolved = Assert-DirectLocalPath $Path
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $content = [System.IO.File]::ReadAllText($resolved, $strictUtf8)
    $options = [System.Text.RegularExpressions.RegexOptions]::Multiline -bor
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    foreach ($entry in $Values.GetEnumerator()) {
        $pattern = '^[\t ]*{0}(?:(?:[\t ]*(?:=|:)[\t ]*)|[\t ]+)[^\r\n]*(?=\r?$)' -f
            [regex]::Escape([string]$entry.Key)
        if ([regex]::Matches($content, $pattern, $options).Count -ne 1) {
            throw "FABRIC_FEDERATION_GUI_PROXY_PROPERTY_COUNT_INVALID: $($entry.Key)"
        }
        $replacement = '{0}={1}' -f [string]$entry.Key, [string]$entry.Value
        $content = [regex]::Replace($content, $pattern, $replacement, $options)
    }
    [System.IO.File]::WriteAllText($resolved, $content, [System.Text.UTF8Encoding]::new($false))
    $readback = [System.IO.File]::ReadAllText($resolved, $strictUtf8)
    foreach ($entry in $Values.GetEnumerator()) {
        $exact = '^{0}={1}(?=\r?$)' -f
            [regex]::Escape([string]$entry.Key), [regex]::Escape([string]$entry.Value)
        if ([regex]::Matches($readback, $exact, $options).Count -ne 1) {
            throw "FABRIC_FEDERATION_GUI_PROXY_PROPERTY_READBACK_INVALID: $($entry.Key)"
        }
    }
}

function Write-BungeeConfiguration(
        [string]$Path,
        [int]$ProxyPort,
        [int]$PaperPort) {
    Write-Utf8 $Path @"
ip_forward: false
online_mode: false
forge_support: false
listeners:
- query_port: 25577
  motd: '&1MCAce federation GUI smoke'
  tab_list: GLOBAL_PING
  query_enabled: false
  proxy_protocol: false
  forced_hosts: {}
  ping_passthrough: false
  priorities:
  - lobby
  bind_local_address: true
  host: 127.0.0.1:$ProxyPort
  max_players: 20
  tab_size: 60
  force_default_server: true
timeout: 30000
connection_throttle: 4000
connection_throttle_limit: 3
disabled_commands: []
servers:
  lobby:
    motd: '&1MCAce federation Paper'
    address: 127.0.0.1:$PaperPort
    restricted: false
"@
}

function Initialize-ProxyRuntime(
        [string]$Side,
        [string]$Kind,
        [string]$Root,
        [int]$ProxyPort,
        [int]$PaperPort,
        [string]$VelocityServerJar,
        [string]$BungeeServerJar) {
    $plugins = New-ExclusiveOwnedDirectory (Join-Path $Root 'plugins') $Root
    if ($Kind -ceq 'VELOCITY') {
        $serverJar = Join-Path $Root 'velocity.jar'
        Copy-Item -LiteralPath $VelocityServerJar -Destination $serverJar
        Copy-Item -LiteralPath $velocityPlugin -Destination (Join-Path $plugins 'mcace.jar')
        Expand-VelocityConfiguration $serverJar (Join-Path $Root 'velocity.toml') $ProxyPort $PaperPort
        $dataDirectory = Join-Path $plugins 'mcace'
        $shutdownCommand = 'end'
    } else {
        $serverJar = Join-Path $Root 'BungeeCord.jar'
        Copy-Item -LiteralPath $BungeeServerJar -Destination $serverJar
        Copy-Item -LiteralPath $bungeePlugin -Destination (Join-Path $plugins 'mcace.jar')
        Write-BungeeConfiguration (Join-Path $Root 'config.yml') $ProxyPort $PaperPort
        $dataDirectory = Join-Path $plugins 'MCAce'
        $shutdownCommand = 'end'
    }
    return [pscustomobject]@{
        Side = $Side
        Kind = $Kind
        Root = $Root
        ServerJar = $serverJar
        DataDirectory = $dataDirectory
        ProxyPort = $ProxyPort
        PaperPort = $PaperPort
        ShutdownCommand = $shutdownCommand
    }
}

function Start-ProxyRuntime([object]$Runtime, [string]$Phase) {
    return Start-FederationJavaService `
        ("{0}-{1}-{2}" -f $Runtime.Side.ToLowerInvariant(), $Runtime.Kind.ToLowerInvariant(), $Phase) `
        $Runtime.Root $Runtime.ServerJar '512m' @()
}

function Wait-ProxyReady([object]$Runtime, $Service) {
    if ($Runtime.Kind -ceq 'VELOCITY') {
        Wait-ServiceRegex $Service 'MCAce Phase 2 handshake initialized' 150
        Wait-ServiceRegex $Service ('Listening on /127\.0\.0\.1:{0}' -f $Runtime.ProxyPort) 150
    } else {
        Wait-ServiceRegex $Service 'MCAce BungeeCord adapter enabled' 150
        Wait-ServiceRegex $Service ('Listening on /127\.0\.0\.1:{0}' -f $Runtime.ProxyPort) 150
    }
    $null = Assert-LoopbackListener $Service $Runtime.ProxyPort
}

function Get-ProxyIdentity([object]$Runtime) {
    $publicPath = Assert-DirectLocalPath (Join-Path $Runtime.DataDirectory 'identity\server-public-key.txt')
    $privatePath = Assert-DirectLocalPath (Join-Path $Runtime.DataDirectory 'identity\server-private-key.pk8')
    $publicText = (Get-Content -LiteralPath $publicPath -Raw -ErrorAction Stop).Trim()
    try { $publicBytes = [Convert]::FromBase64String($publicText) }
    catch { throw 'FABRIC_FEDERATION_GUI_PROXY_PUBLIC_KEY_INVALID' }
    if ($publicBytes.Length -lt 32 -or (Get-Item -LiteralPath $privatePath).Length -le 0L) {
        throw 'FABRIC_FEDERATION_GUI_PROXY_IDENTITY_INCOMPLETE'
    }
    return [pscustomobject]@{
        public_text = $publicText
        key_id_sha256 = Get-Sha256HexFromBytes $publicBytes
    }
}

function Configure-ProxyProduct(
        [object]$Runtime,
        [string]$NetworkId,
        [string]$BuildId) {
    $config = Assert-DirectLocalPath (Join-Path $Runtime.DataDirectory 'mcace.properties')
    if ($Runtime.Kind -ceq 'VELOCITY') {
        Set-ExactConfigProperties $config ([ordered]@{
            'enforcement.mode' = 'MONITOR'
            'handshake.timeout.seconds' = '30'
            'policy.server-id' = $NetworkId
            'policy.minecraft-versions' = [string]$fabricDescriptor.minecraft_version
            'policy.client-build-ids' = $BuildId
        })
    } else {
        Set-ExactConfigProperties $config ([ordered]@{
            'server.id' = $NetworkId
            'minecraft.version' = [string]$fabricDescriptor.minecraft_version
            'client.build-id' = $BuildId
            'handshake.timeout.seconds' = '30'
            'disposition.enforcement.mode' = 'MONITOR'
        })
    }
}

function Write-FederationConfiguration(
        [object]$Runtime,
        [string]$LocalNetworkId,
        [string]$PeerNetworkId,
        [object]$PeerIdentity,
        [ValidateSet('ISSUE_TO', 'ACCEPT_FROM')]
        [string]$Capability) {
    if ($PeerIdentity.key_id_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]::IsNullOrWhiteSpace([string]$PeerIdentity.public_text)) {
        throw 'FABRIC_FEDERATION_GUI_FEDERATION_PEER_IDENTITY_INVALID'
    }
    Write-Utf8 (Join-Path $Runtime.DataDirectory 'federation.properties') @"
schema.version=1
enabled=true
local.network-id=$LocalNetworkId
assertion.ttl.seconds=$FederationAssertionTtlSeconds
peer.ids=$PeerNetworkId
peer.$PeerNetworkId.public-key-x509-base64=$($PeerIdentity.public_text)
peer.$PeerNetworkId.key-id-sha256=$($PeerIdentity.key_id_sha256)
peer.$PeerNetworkId.capabilities=$Capability
"@
}

function Probe-FederationReady(
        [object]$Runtime,
        $Service,
        [string]$NetworkId) {
    $pattern = 'MCAce: federation enabled=true configured=true audit=HEALTHY audit_backlog=0 ' +
        'audit_committed=[0-9]+ audit_failures=0 local={0} peers=1 pending=0 observations=0' -f
        [regex]::Escape($NetworkId)
    $baseline = Get-ServiceRegexCount $Service $pattern
    Send-ServiceCommand $Service 'mcacefederation status'
    Wait-NewServiceRegex $Service $pattern $baseline 30
}

function Initialize-PaperRuntime(
        [string]$Side,
        [string]$Root,
        [int]$Port,
        [string]$PaperServerJar,
        [string]$ProxyPublicKeyPath) {
    foreach ($directoryName in @('cache', 'libraries', 'versions')) {
        Copy-Item -LiteralPath (Assert-DirectLocalPath (Join-Path $preparedPaperRoot $directoryName) -Directory) `
            -Destination $Root -Recurse
    }
    $plugins = New-ExclusiveOwnedDirectory (Join-Path $Root 'plugins') $Root
    $data = New-ExclusiveOwnedDirectory (Join-Path $plugins 'MCAce') $plugins
    Copy-Item -LiteralPath $paperPlugin -Destination (Join-Path $plugins 'mcace.jar')
    Copy-Item -LiteralPath $PaperServerJar -Destination (Join-Path $Root 'paper.jar')
    Copy-Item -LiteralPath $ProxyPublicKeyPath -Destination (Join-Path $data 'proxy-public-key.txt')
    Write-Utf8 (Join-Path $Root 'eula.txt') "eula=true`n"
    Write-Utf8 (Join-Path $Root 'server.properties') `
        "online-mode=false`nserver-ip=127.0.0.1`nserver-port=$Port`nenable-query=false`nmotd=MCAce federation $Side`n"
    return [pscustomobject]@{
        Side = $Side
        Root = $Root
        Port = $Port
        ServerJar = Join-Path $Root 'paper.jar'
    }
}

function Start-PaperRuntime([object]$Runtime) {
    return Start-FederationJavaService `
        ("{0}-paper" -f $Runtime.Side.ToLowerInvariant()) $Runtime.Root $Runtime.ServerJar '1024m' @('--nogui')
}

function Wait-PaperReady([object]$Runtime, $Service) {
    Wait-ServiceRegex $Service ('Starting Minecraft server on 127\.0\.0\.1:{0}' -f $Runtime.Port) 300
    Wait-ServiceRegex $Service 'MCAce signed proxy admission channel enabled' 300
    Wait-ServiceRegex $Service 'Done \(' 300
    $null = Assert-LoopbackListener $Service $Runtime.Port
}

function Get-RunLocalRuntimeBinding(
        [object]$SourceRuntime,
        [object]$TargetRuntime,
        [object]$SourcePaperRuntime,
        [object]$TargetPaperRuntime) {
    $sourcePrepared = Get-PreparedTreeBinding $SourcePaperRuntime.Root
    $targetPrepared = Get-PreparedTreeBinding $TargetPaperRuntime.Root
    return [ordered]@{
        source_proxy_server_sha256 = Get-Sha256 (Assert-DirectLocalPath $SourceRuntime.ServerJar)
        target_proxy_server_sha256 = Get-Sha256 (Assert-DirectLocalPath $TargetRuntime.ServerJar)
        source_proxy_plugin_sha256 = Get-Sha256 (Assert-DirectLocalPath (Join-Path $SourceRuntime.Root 'plugins\mcace.jar'))
        target_proxy_plugin_sha256 = Get-Sha256 (Assert-DirectLocalPath (Join-Path $TargetRuntime.Root 'plugins\mcace.jar'))
        source_paper_server_sha256 = Get-Sha256 (Assert-DirectLocalPath $SourcePaperRuntime.ServerJar)
        target_paper_server_sha256 = Get-Sha256 (Assert-DirectLocalPath $TargetPaperRuntime.ServerJar)
        source_paper_plugin_sha256 = Get-Sha256 (Assert-DirectLocalPath (Join-Path $SourcePaperRuntime.Root 'plugins\mcace.jar'))
        target_paper_plugin_sha256 = Get-Sha256 (Assert-DirectLocalPath (Join-Path $TargetPaperRuntime.Root 'plugins\mcace.jar'))
        source_prepared_tree_sha256 = $sourcePrepared.sha256
        target_prepared_tree_sha256 = $targetPrepared.sha256
        source_prepared_file_count = [int]$sourcePrepared.file_count
        target_prepared_file_count = [int]$targetPrepared.file_count
        source_prepared_total_size = [long]$sourcePrepared.total_size
        target_prepared_total_size = [long]$targetPrepared.total_size
    }
}

function Assert-RunLocalRuntimeBinding(
        [System.Collections.IDictionary]$Actual,
        [System.Collections.IDictionary]$Current) {
    $sourceExpectedProxy = if ($SourceProxy -ceq 'VELOCITY') {
        $Current.velocity_server_sha256
    } else { $Current.bungee_server_sha256 }
    $targetExpectedProxy = if ($TargetProxy -ceq 'VELOCITY') {
        $Current.velocity_server_sha256
    } else { $Current.bungee_server_sha256 }
    $sourceExpectedPlugin = if ($SourceProxy -ceq 'VELOCITY') {
        $Current.velocity_plugin_sha256
    } else { $Current.bungee_plugin_sha256 }
    $targetExpectedPlugin = if ($TargetProxy -ceq 'VELOCITY') {
        $Current.velocity_plugin_sha256
    } else { $Current.bungee_plugin_sha256 }
    $expected = [ordered]@{
        source_proxy_server_sha256 = $sourceExpectedProxy
        target_proxy_server_sha256 = $targetExpectedProxy
        source_proxy_plugin_sha256 = $sourceExpectedPlugin
        target_proxy_plugin_sha256 = $targetExpectedPlugin
        source_paper_server_sha256 = $Current.paper_server_sha256
        target_paper_server_sha256 = $Current.paper_server_sha256
        source_paper_plugin_sha256 = $Current.paper_plugin_sha256
        target_paper_plugin_sha256 = $Current.paper_plugin_sha256
        source_prepared_tree_sha256 = $Current.paper_prepared_tree_sha256
        target_prepared_tree_sha256 = $Current.paper_prepared_tree_sha256
        source_prepared_file_count = $Current.paper_prepared_file_count
        target_prepared_file_count = $Current.paper_prepared_file_count
        source_prepared_total_size = $Current.paper_prepared_total_size
        target_prepared_total_size = $Current.paper_prepared_total_size
    }
    Assert-BindingUnchanged $expected $Actual 'FABRIC_FEDERATION_GUI_RUN_LOCAL_RUNTIME_MISMATCH'
}

function Get-FileText([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if ($null -eq $content) { return '' }
    return [string]$content
}

function Get-FileLiteralCount([string]$Path, [string]$Marker) {
    return [regex]::Matches(
        (Get-FileText $Path), [regex]::Escape($Marker),
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
}

function Get-FileRegexCount([string]$Path, [string]$Pattern) {
    return [regex]::Matches(
        (Get-FileText $Path), $Pattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
}

function Wait-NewFileRegex(
        $Service,
        [string]$Path,
        [string]$Pattern,
        [int]$BaselineCount,
        [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Get-FileRegexCount $Path $Pattern) -gt $BaselineCount) { return }
        if ($Service.Process.HasExited) {
            throw "FABRIC_FEDERATION_GUI_SERVICE_EXITED_BEFORE_NEW_FILE_REGEX: $($Service.Name)"
        }
        Start-Sleep -Milliseconds 100
    }
    throw "FABRIC_FEDERATION_GUI_NEW_FILE_REGEX_TIMEOUT: $($Service.Name)"
}

function Wait-FileLiteralCount(
        $Service,
        [string]$Path,
        [string]$Marker,
        [int]$MinimumCount,
        [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Get-FileLiteralCount $Path $Marker) -ge $MinimumCount) { return }
        if ($Service.Process.HasExited) {
            throw "FABRIC_FEDERATION_GUI_CLIENT_EXITED_BEFORE_MARKER: $Marker"
        }
        Start-Sleep -Seconds 1
    }
    throw "FABRIC_FEDERATION_GUI_CLIENT_MARKER_TIMEOUT: $Marker"
}

function Wait-FileRegexMatch(
        $Service,
        [string]$Path,
        [string]$Pattern,
        [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $match = [regex]::Match(
            (Get-FileText $Path), $Pattern,
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
        if ($match.Success) { return $match }
        if ($Service.Process.HasExited) {
            throw "FABRIC_FEDERATION_GUI_SERVICE_EXITED_BEFORE_FILE_REGEX: $($Service.Name)"
        }
        Start-Sleep -Milliseconds 100
    }
    throw "FABRIC_FEDERATION_GUI_FILE_REGEX_TIMEOUT: $($Service.Name)"
}

function Assert-ExactHumanGuiMarkers([string]$FabricLogPath) {
    foreach ($marker in $requiredHumanGuiMarkers) {
        if ((Get-FileLiteralCount $FabricLogPath $marker) -ne 1) {
            throw "FABRIC_FEDERATION_GUI_EXACT_HUMAN_MARKER_ONCE_REQUIRED: $marker"
        }
    }
}

function Assert-ProductFederationGuiContract {
    $rootClient = Assert-DirectLocalPath (Join-Path $repoRoot `
        'mcace-client-fabric\src\main\java\com\ellan\mcace\fabric\MCAceFabricClient.java')
    $modernClient = Assert-DirectLocalPath (Join-Path $repoRoot `
        'fabric-modern\src\main\java\com\ellan\mcace\fabric\MCAceFabricClient.java')
    $vaultPath = Assert-DirectLocalPath (Join-Path $repoRoot `
        'mcace-client-common\src\main\java\com\ellan\mcace\client\federation\FederationTokenVault.java')
    $federationRuntimePath = Assert-DirectLocalPath (Join-Path $repoRoot `
        'mcace-core\src\main\java\com\ellan\mcace\core\federation\FederationRuntime.java')
    $federationDocumentsPath = Assert-DirectLocalPath (Join-Path $repoRoot `
        'mcace-protocol\src\main\java\com\ellan\mcace\protocol\federation\FederationDocuments.java')
    foreach ($clientPath in @($rootClient, $modernClient)) {
        $content = Get-Content -LiteralPath $clientPath -Raw -ErrorAction Stop
        foreach ($marker in $requiredHumanGuiMarkers) {
            if ([regex]::Matches($content, [regex]::Escape($marker)).Count -ne 1) {
                throw "FABRIC_FEDERATION_GUI_PRODUCT_MARKER_CONTRACT_INVALID: $marker"
            }
        }
        foreach ($call in @(
                'federationVault.onConnectionClosed()', 'federationVault.cancelTargetClaims()',
                'federationVault.newTargetHandshake(', 'federationVault.preparePresentation(',
                'federationVault.commit(prepared)', 'federationVault.close()')) {
            if (-not $content.Contains($call)) {
                throw "FABRIC_FEDERATION_GUI_PRODUCT_LIFECYCLE_CONTRACT_MISSING: $call"
            }
        }
    }
    $vault = Get-Content -LiteralPath $vaultPath -Raw -ErrorAction Stop
    foreach ($contract in @(
            'public synchronized void onConnectionClosed()',
            'public synchronized void cancelTargetClaims()',
            'if (entry.boundTargetKeyVerified || entry.sourceConnectionClosed)',
            'entry.sourceConnectionClosed = true',
            'if (entry.boundTargetKeyVerified)',
            'public synchronized void close()')) {
        if (-not $vault.Contains($contract)) {
            throw "FABRIC_FEDERATION_GUI_VAULT_DISCONNECT_CONTRACT_MISSING: $contract"
        }
    }
    $federationRuntime = Get-Content -LiteralPath $federationRuntimePath -Raw -ErrorAction Stop
    $federationDocuments = Get-Content -LiteralPath $federationDocumentsPath -Raw -ErrorAction Stop
    foreach ($contract in @(
            'FederationDocuments.issueConsentRequest(',
            'clock, current.assertionLifetime(), secureRandom',
            'Instant expiresAt = Instant.ofEpochMilli(verified.expiresAtEpochMs())',
            'if (!clock.instant().isBefore(entry.getValue().expiresAt()))')) {
        if (-not $federationRuntime.Contains($contract)) {
            throw "FABRIC_FEDERATION_GUI_ASSERTION_EXPIRY_CONTRACT_MISSING: $contract"
        }
    }
    foreach ($contract in @(
            'long issuedAt = clock.millis()',
            'long expiresAt = safeAdd(issuedAt, lifetimeMillis, "federation expiry overflow")')) {
        if (-not $federationDocuments.Contains($contract)) {
            throw "FABRIC_FEDERATION_GUI_ASSERTION_TIMESTAMP_CONTRACT_MISSING: $contract"
        }
    }
}

function Get-DistinctLoopbackPorts([int]$Count) {
    $ports = [System.Collections.Generic.HashSet[int]]::new()
    while ($ports.Count -lt $Count) { [void]$ports.Add((Get-FreeLoopbackPort)) }
    return @($ports)
}

function Assert-FederationRunLeaf([string]$Leaf) {
    if ($Leaf -cnotmatch '^[0-9]{8}T[0-9]{9}Z-(?:1_21_11|26_1_2|26_2)-(?:VELOCITY|BUNGEE)-to-(?:VELOCITY|BUNGEE)-[0-9a-f]{32}$') {
        throw 'FABRIC_FEDERATION_GUI_CSPRNG_RUN_LEAF_REQUIRED'
    }
}

function Assert-OwnedRunDirectory([string]$RunDirectory) {
    $root = Assert-DirectLocalPath $evidenceRunsRoot -Directory
    $run = Assert-OwnedTreeNoReparse $RunDirectory
    Assert-FederationRunLeaf ([System.IO.Path]::GetFileName($run))
    if (-not [System.IO.Path]::GetDirectoryName($run).Equals(
            $root, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'FABRIC_FEDERATION_GUI_RUN_PARENT_INVALID'
    }
    return $run
}

function Remove-OwnedRunDirectory([string]$RunDirectory) {
    if (-not (Test-Path -LiteralPath $RunDirectory -PathType Container)) { return }
    $run = Assert-OwnedRunDirectory $RunDirectory
    Remove-Item -LiteralPath $run -Recurse -Force
}

function Clear-OwnedRunForEvidence([string]$RunDirectory) {
    $run = Assert-OwnedRunDirectory $RunDirectory
    foreach ($entry in @(Get-ChildItem -LiteralPath $run -Force)) {
        $resolved = [System.IO.Path]::GetFullPath($entry.FullName)
        if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'FABRIC_FEDERATION_GUI_REPARSE_DIAGNOSTIC_REJECTED'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
    if (@(Get-ChildItem -LiteralPath $run -Force).Count -ne 0) {
        throw 'FABRIC_FEDERATION_GUI_RAW_RUN_CONTENT_RESIDUE'
    }
}

$script:ServerAssets = Resolve-FederationServerAssets
$preparedPaperRoot = [string]$script:ServerAssets.prepared_root

if ($ReportOnly) {
    $current = Get-CurrentBinding
    Assert-ReportOnlyExpectedBinding $current
    $latest = Get-LatestCompleteEvidenceReport
    if ($null -eq $latest) {
        throw 'FABRIC_FEDERATION_GUI_TARGET_BOUND_V2_EVIDENCE_TRIPLET_REQUIRED'
    }
    $null = Assert-EvidenceTriplet $latest $current $SourceProxy $TargetProxy
    Write-Output "FABRIC_FEDERATION_GUI_HANDOFF_PASS|report-only|target=$FabricTarget|source=$SourceProxy|target_proxy=$TargetProxy"
    exit 0
}

if (-not $EnablementHumanAttested) {
    throw 'FABRIC_FEDERATION_GUI_ONE_EXPLICIT_HUMAN_ATTESTATION_REQUIRED'
}
if ($requiredHumanGuiMarkers.Count -ne 5) {
    throw 'FABRIC_FEDERATION_GUI_ENABLEMENT_MARKER_CONTRACT_REQUIRED'
}

Assert-ProductFederationGuiContract
$script:RootJava = Resolve-RootJava21
$script:TargetJava = Resolve-TargetJava
$script:RootJavaPath = $script:RootJava.path
$script:TargetJavaPath = $script:TargetJava.path
$script:OfflineGradle = Resolve-OfflineGradle961

$repoRoot = Assert-DirectLocalPath $repoRoot -Directory
$buildRoot = Initialize-SafeOwnedDirectory (Join-Path $repoRoot 'build') $repoRoot
$evidenceRoot = Initialize-SafeOwnedDirectory $evidenceRoot $buildRoot
$evidenceRunsRoot = Initialize-SafeOwnedDirectory $evidenceRunsRoot $evidenceRoot
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
$runToken = New-SmokeRunToken
Assert-SmokeRunToken $runToken
$runTokenJvmArgument = "-Dmcace.smoke.run-token=$runToken"
$fabricSmokeBuildId = "platform-smoke-$runId"
$runLeaf = '{0}-{1}-{2}-to-{3}-{4}' -f
    $runId, $FabricTarget.Replace('.', '_'), $SourceProxy, $TargetProxy, $runToken
Assert-FederationRunLeaf $runLeaf
$runRoot = Join-Path $evidenceRunsRoot $runLeaf

try {
$preBuildInput = Get-ImmutableInputBinding
$smokeBuildProperties = @(
    '-PmcaceSmokeArtifactMode=true',
    "-PmcaceClientBuildId=$fabricSmokeBuildId",
    "-PmcaceSmokeRunToken=$runToken"
)
$rootBuildTasks = @(
    ':mcace-server-velocity:shadowJar',
    ':mcace-server-bungeecord:shadowJar',
    ':mcace-server-paper:shadowJar'
)
if ([int]$fabricDescriptor.java_major -eq 21) {
    $rootBuildTasks += [string]$fabricDescriptor.build_task
} else {
    $rootBuildTasks += ':stageModernFabricDeps'
}
Invoke-PinnedOfflineGradle $script:RootJavaPath $repoRoot $rootBuildTasks `
    $smokeBuildProperties $true 'FABRIC_FEDERATION_GUI_ROOT_JDK21_BUILD_FAILED'
if ([int]$fabricDescriptor.java_major -eq 25) {
    $modernProperties = @($smokeBuildProperties) + @(
        "-PmcaceRootDepsDir=$stagedModernDependencies",
        "-PmcaceProductVersion=$fabricArtifactVersion"
    )
    Invoke-PinnedOfflineGradle $script:TargetJavaPath ([string]$fabricDescriptor.gradle_project_directory) `
        @([string]$fabricDescriptor.build_task) $modernProperties $true `
        'FABRIC_FEDERATION_GUI_MODERN_JDK25_BUILD_FAILED'
}
foreach ($artifact in @($fabricArtifactJar, $velocityPlugin, $bungeePlugin, $paperPlugin)) {
    $null = Assert-DirectLocalPath $artifact
}
$builtFabricSha256 = Get-Sha256 $fabricArtifactJar
$verificationProperties = @($smokeBuildProperties) + @(
    "-PmcaceSmokeExpectedArtifactSha256=$builtFabricSha256"
)
if ([int]$fabricDescriptor.java_major -eq 25) {
    $verificationProperties += @(
        "-PmcaceRootDepsDir=$stagedModernDependencies",
        "-PmcaceProductVersion=$fabricArtifactVersion"
    )
}
Invoke-PinnedOfflineGradle $script:TargetJavaPath ([string]$fabricDescriptor.gradle_project_directory) `
    @([string]$fabricDescriptor.verify_task) $verificationProperties $false `
    'FABRIC_FEDERATION_GUI_FABRIC_ARTIFACT_VERIFY_FAILED'

$currentBinding = Get-CurrentBinding
$postBuildInput = Get-ImmutableInputBinding
Assert-BindingUnchanged $preBuildInput $postBuildInput 'FABRIC_FEDERATION_GUI_IMMUTABLE_INPUT_CHANGED_DURING_BUILD'
if ([string]$currentBinding.fabric_build_id -cne $fabricSmokeBuildId) {
    throw 'FABRIC_FEDERATION_GUI_BUILT_FABRIC_IDENTITY_MISMATCH'
}
foreach ($entry in @(
        @($velocityPlugin, 'com/ellan/mcace/velocity/MCAceVelocityChannels.class'),
        @($bungeePlugin, 'com/ellan/mcace/bungeecord/BungeeMCAceChannels.class'))) {
    if (-not (Test-JarEntry $entry[0] $entry[1])) {
        throw 'FABRIC_FEDERATION_GUI_PROXY_TRANSPORT_CLASS_REQUIRED'
    }
}
$fabricExpectedArtifactMarker =
    "MCACE_FABRIC_ARTIFACT_LOADED version=$fabricArtifactVersion build_id=$fabricSmokeBuildId" +
    " code_source_sha256=$($currentBinding.fabric_artifact_sha256)"

$velocityServerJar = Get-VerifiedArtifact $script:ServerAssets.velocity
$bungeeServerJar = Get-VerifiedBungeeArtifact $script:ServerAssets.bungee
$paperServerJar = Get-VerifiedArtifact $script:ServerAssets.paper
} catch {
    try { Stop-RunTokenJavaProcesses $runToken } catch { }
    throw
}

$sourceService = $null
$targetService = $null
$sourcePaperService = $null
$targetPaperService = $null
$fabricClient = $null
$sourcePaperRuntime = $null
$targetPaperRuntime = $null
$sourceRuntime = $null
$targetRuntime = $null
$allPorts = @()
$runRootCreated = $false
$runLocalBefore = $null
$failure = $null
$runtimeAssertionsComplete = $false
$clientShutdownCompleted = $false
$sourceLocalAuthVerified = $false
$sourcePaperAdmissionVerified = $false
$sourceGrantReadyObserved = $false
$sourceDisconnectedBeforeTargetAuth = $false
$targetLocalAuthVerified = $false
$targetPaperAdmissionVerified = $false
$targetObservationRecorded = $false
$targetSubjectBound = $false
$targetObservationCountOne = $false
$targetObservationOneBeforeExpiry = $false
$targetSessionConnectedThroughExpiry = $false
$observationExpired = $false
$targetObservationZero = $false
$localStateUnchanged = $false
$presentationSent = $false

try {
    # Create mutable run state only after the pinned build and artifact verification succeeds so a
    # build/preflight failure cannot strand a half-created run leaf outside the cleanup boundary.
    $runRoot = New-ExclusiveOwnedDirectory $runRoot $evidenceRunsRoot
    $runRootCreated = $true
    $sourceProxyRoot = New-ExclusiveOwnedDirectory (Join-Path $runRoot 'source-proxy') $runRoot
    $targetProxyRoot = New-ExclusiveOwnedDirectory (Join-Path $runRoot 'target-proxy') $runRoot
    $sourcePaperRoot = New-ExclusiveOwnedDirectory (Join-Path $runRoot 'source-paper') $runRoot
    $targetPaperRoot = New-ExclusiveOwnedDirectory (Join-Path $runRoot 'target-paper') $runRoot
    $fabricRoot = New-ExclusiveOwnedDirectory (Join-Path $runRoot 'fabric-client') $runRoot

    $ports = Get-DistinctLoopbackPorts 4
    $sourceProxyPort = [int]$ports[0]
    $targetProxyPort = [int]$ports[1]
    $sourcePaperPort = [int]$ports[2]
    $targetPaperPort = [int]$ports[3]
    $allPorts = @($sourceProxyPort, $targetProxyPort, $sourcePaperPort, $targetPaperPort)

    $sourceRuntime = Initialize-ProxyRuntime `
        'SOURCE' $SourceProxy $sourceProxyRoot $sourceProxyPort $sourcePaperPort `
        $velocityServerJar $bungeeServerJar
    $targetRuntime = Initialize-ProxyRuntime `
        'TARGET' $TargetProxy $targetProxyRoot $targetProxyPort $targetPaperPort `
        $velocityServerJar $bungeeServerJar

    # Bootstrap both isolated proxies only far enough to create their persistent identities and
    # strict default product/federation files. No client connects during this phase.
    $sourceService = Start-ProxyRuntime $sourceRuntime 'bootstrap'
    Wait-ProxyReady $sourceRuntime $sourceService
    $targetService = Start-ProxyRuntime $targetRuntime 'bootstrap'
    Wait-ProxyReady $targetRuntime $targetService
    $sourceIdentity = Get-ProxyIdentity $sourceRuntime
    $targetIdentity = Get-ProxyIdentity $targetRuntime
    Stop-FederationJavaService $sourceService $sourceRuntime.ShutdownCommand
    $sourceService = $null
    Stop-FederationJavaService $targetService $targetRuntime.ShutdownCommand
    $targetService = $null

    Configure-ProxyProduct $sourceRuntime 'mcace-source' $fabricSmokeBuildId
    Configure-ProxyProduct $targetRuntime 'mcace-target' $fabricSmokeBuildId
    Write-FederationConfiguration `
        $sourceRuntime 'mcace-source' 'mcace-target' $targetIdentity 'ISSUE_TO'
    Write-FederationConfiguration `
        $targetRuntime 'mcace-target' 'mcace-source' $sourceIdentity 'ACCEPT_FROM'

    $sourceService = Start-ProxyRuntime $sourceRuntime 'active'
    Wait-ProxyReady $sourceRuntime $sourceService
    $targetService = Start-ProxyRuntime $targetRuntime 'active'
    Wait-ProxyReady $targetRuntime $targetService
    Probe-FederationReady $sourceRuntime $sourceService 'mcace-source'
    Probe-FederationReady $targetRuntime $targetService 'mcace-target'

    $sourcePinPath = Assert-DirectLocalPath `
        (Join-Path $sourceRuntime.DataDirectory 'identity\server-public-key.txt')
    $targetPinPath = Assert-DirectLocalPath `
        (Join-Path $targetRuntime.DataDirectory 'identity\server-public-key.txt')
    $sourcePaperRuntime = Initialize-PaperRuntime `
        'source' $sourcePaperRoot $sourcePaperPort $paperServerJar $sourcePinPath
    $targetPaperRuntime = Initialize-PaperRuntime `
        'target' $targetPaperRoot $targetPaperPort $paperServerJar $targetPinPath
    $runLocalBefore = Get-RunLocalRuntimeBinding `
        $sourceRuntime $targetRuntime $sourcePaperRuntime $targetPaperRuntime
    Assert-RunLocalRuntimeBinding $runLocalBefore $currentBinding

    $sourcePaperService = Start-PaperRuntime $sourcePaperRuntime
    Wait-PaperReady $sourcePaperRuntime $sourcePaperService
    $targetPaperService = Start-PaperRuntime $targetPaperRuntime
    Wait-PaperReady $targetPaperRuntime $targetPaperService

    $fabricConfig = New-ExclusiveOwnedDirectory (Join-Path $fabricRoot 'config') $fabricRoot
    $fabricMCAceConfig = New-ExclusiveOwnedDirectory (Join-Path $fabricConfig 'mcace') $fabricConfig
    $null = New-ExclusiveOwnedDirectory (Join-Path $fabricRoot 'mods') $fabricRoot
    $sourceAddress = "127.0.0.1:$sourceProxyPort"
    $targetAddress = "127.0.0.1:$targetProxyPort"
    $sourcePinValue = (Get-Content -LiteralPath $sourcePinPath -Raw -ErrorAction Stop).Trim()
    $targetPinValue = (Get-Content -LiteralPath $targetPinPath -Raw -ErrorAction Stop).Trim()
    $sourcePropertyAddress = $sourceAddress.Replace(':', '\:')
    $targetPropertyAddress = $targetAddress.Replace(':', '\:')
    Write-Utf8 (Join-Path $fabricMCAceConfig 'server-keys.properties') `
        "$sourcePropertyAddress=$sourcePinValue`n$targetPropertyAddress=$targetPinValue`n"
    Write-Utf8 (Join-Path $fabricRoot 'options.txt') "fov:0.5`nrenderDistance:8`n"

    Write-Host ''
    Write-Host "SOURCE HUMAN PHASE ($sourceAddress): approve the single visible connection-level Enable MCAce prompt exactly once."
    Write-Host 'This runner does not click, focus, type into, or automate the Fabric window.'
    $fabricClient = Start-FabricClient `
        $fabricRoot $sourceAddress $true ([string]$currentBinding.fabric_artifact_sha256)
    $fabricLog = Join-Path $fabricRoot 'logs\latest.log'
    Wait-FileLiteralCount $fabricClient $fabricLog $fabricExpectedArtifactMarker 1 300
    Assert-FabricArtifactMarker $fabricLog $fabricExpectedArtifactMarker
    Wait-FileLiteralCount $fabricClient $fabricLog 'MCAce Fabric client initialized' 1 300
    Wait-FileLiteralCount $fabricClient $fabricLog `
        'MCAce session verified at trust level VERIFIED with risk score 0' 1 60
    $sourceLocalAuthVerified = $true
    $sourcePaperLog = Join-Path $sourcePaperRoot 'logs\latest.log'
    $uuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-' +
        '[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    $verifiedPaperAdmissionPattern = 'Accepted signed MCAce admission state for ' +
        "(?<subject>$uuidPattern): admission=VERIFIED, trust=VERIFIED, risk=0"
    $sourcePaperAdmission = Wait-FileRegexMatch `
        $sourcePaperService $sourcePaperLog $verifiedPaperAdmissionPattern 30
    $sourceSubjectId = [string]$sourcePaperAdmission.Groups['subject'].Value
    $sourcePaperAdmissionVerified = $true
    $playerName = Get-FabricDevelopmentPlayerName $fabricLog

    $issuePattern = 'MCAce: federation issue status=CONSENT_ISSUED'
    $issueBaseline = Get-FileRegexCount $sourceService.StdoutPath $issuePattern
    $consentIssuedAt = [DateTimeOffset]::UtcNow
    $earliestAssertionExpiry = $consentIssuedAt.AddSeconds($FederationAssertionTtlSeconds)
    $targetEvidenceDeadline = $earliestAssertionExpiry.AddSeconds(-15)
    $preExpiryProbeAt = $earliestAssertionExpiry.AddSeconds(-8)
    Send-ServiceCommand $sourceService "mcacefederation issue $playerName mcace-target"
    Wait-NewFileRegex $sourceService $sourceService.StdoutPath $issuePattern $issueBaseline 30
    $consentIssueObservedAt = [DateTimeOffset]::UtcNow
    $latestAssertionExpiry = $consentIssueObservedAt.AddSeconds($FederationAssertionTtlSeconds)
    Wait-FileLiteralCount $fabricClient $fabricLog $requiredHumanGuiMarkers[0] 1 30
    Wait-FileLiteralCount $fabricClient $fabricLog $requiredHumanGuiMarkers[1] 1 30
    Wait-FileLiteralCount $fabricClient $fabricLog `
        $requiredHumanGuiMarkers[2] 1 $HumanTransitionTimeoutSeconds
    Wait-FileLiteralCount $fabricClient $fabricLog $requiredHumanGuiMarkers[3] 1 30
    $grantReadyPattern = 'MCAce federation consent response status=GRANT_READY player=' +
        [regex]::Escape($sourceSubjectId)
    $null = Wait-FileRegexMatch $sourceService $sourceService.StdoutPath $grantReadyPattern 30
    $sourceGrantReadyObserved = $true
    Wait-FileLiteralCount $fabricClient $fabricLog `
        'MCAce stored a one-time federation grant in memory only' 1 30

    Write-Host ''
    Write-Host "TARGET HUMAN PHASE: disconnect from source and use Minecraft Direct Connection to join $targetAddress. The accepted connection enablement is inherited; no second prompt is expected."
    Write-Host "Complete this phase with at least 15 seconds remaining in the conservative $FederationAssertionTtlSeconds-second assertion window."
    $transitionTimeout = Get-SecondsUntilDeadline `
        $targetEvidenceDeadline $HumanTransitionTimeoutSeconds `
        'FABRIC_FEDERATION_GUI_TARGET_TRANSITION_WINDOW_EXPIRED'
    Wait-FileLiteralCount $sourcePaperService $sourcePaperLog `
        "$playerName left the game" 1 $transitionTimeout
    $sourceDisconnectedBeforeTargetAuth = $true
    $targetAuthTimeout = Get-SecondsUntilDeadline `
        $targetEvidenceDeadline $HumanTransitionTimeoutSeconds `
        'FABRIC_FEDERATION_GUI_TARGET_AUTH_WINDOW_EXPIRED'
    Wait-FileLiteralCount $fabricClient $fabricLog `
        'MCAce session verified at trust level VERIFIED with risk score 0' 2 $targetAuthTimeout
    $targetLocalAuthVerified = $true
    $targetPaperLog = Join-Path $targetPaperRoot 'logs\latest.log'
    $targetAdmissionTimeout = Get-SecondsUntilDeadline `
        $targetEvidenceDeadline 30 'FABRIC_FEDERATION_GUI_TARGET_ADMISSION_WINDOW_EXPIRED'
    $targetPaperAdmission = Wait-FileRegexMatch `
        $targetPaperService $targetPaperLog $verifiedPaperAdmissionPattern $targetAdmissionTimeout
    $targetSubjectId = [string]$targetPaperAdmission.Groups['subject'].Value
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($sourceSubjectId, $targetSubjectId)) {
        throw 'FABRIC_FEDERATION_GUI_SOURCE_TARGET_SUBJECT_MISMATCH'
    }
    $targetSubjectBound = $true
    $targetPaperAdmissionVerified = $true
    $targetDisconnectMarker = "$playerName left the game"
    $targetDisconnectBaseline = Get-FileLiteralCount $targetPaperLog $targetDisconnectMarker
    Assert-NewPaperVerifiedSnapshot $targetPaperService $targetPaperService.StdoutPath $playerName `
        (Get-SecondsUntilDeadline $targetEvidenceDeadline 10 `
            'FABRIC_FEDERATION_GUI_TARGET_LOCAL_STATE_WINDOW_EXPIRED')
    Wait-FileLiteralCount $fabricClient $fabricLog $requiredHumanGuiMarkers[4] 1 `
        (Get-SecondsUntilDeadline $targetEvidenceDeadline $HumanTransitionTimeoutSeconds `
            'FABRIC_FEDERATION_GUI_TARGET_ENABLEMENT_INHERITANCE_WINDOW_EXPIRED')
    $targetObservationPattern = 'MCAce federation presentation status=OBSERVED player=' +
        [regex]::Escape($targetSubjectId) + ' \(observation-only\)'
    $null = Wait-FileRegexMatch $targetService $targetService.StdoutPath $targetObservationPattern `
        (Get-SecondsUntilDeadline $targetEvidenceDeadline 30 `
            'FABRIC_FEDERATION_GUI_TARGET_OBSERVATION_WINDOW_EXPIRED')
    $targetObservationRecorded = $true
    $presentationSent = $true
    $targetOnePattern = 'MCAce: federation enabled=true configured=true audit=HEALTHY ' +
        'audit_backlog=0 audit_committed=[0-9]+ audit_failures=0 local=mcace-target peers=1 pending=0 observations=1'
    $targetOneBaseline = Get-FileRegexCount $targetService.StdoutPath $targetOnePattern
    Send-ServiceCommand $targetService 'mcacefederation status'
    Wait-NewFileRegex $targetService $targetService.StdoutPath $targetOnePattern $targetOneBaseline `
        (Get-SecondsUntilDeadline $targetEvidenceDeadline 10 `
            'FABRIC_FEDERATION_GUI_TARGET_INITIAL_OBSERVATION_WINDOW_EXPIRED')
    $targetObservationCountOne = $true
    Assert-NewPaperVerifiedSnapshot $targetPaperService $targetPaperService.StdoutPath $playerName `
        (Get-SecondsUntilDeadline $targetEvidenceDeadline 10 `
            'FABRIC_FEDERATION_GUI_TARGET_POST_OBSERVATION_STATE_WINDOW_EXPIRED')
    Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
        $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline
    Assert-ExactHumanGuiMarkers $fabricLog

    # FederationDocuments creates issuedAt/expiresAt while the issue command runs. The pre-send and
    # post-CONSENT_ISSUED timestamps therefore bound the real expiry. Repeated one-count probes near
    # the lower bound plus accepting zero only after the upper bound reject premature cleanup.
    while ([DateTimeOffset]::UtcNow -lt $preExpiryProbeAt) {
        Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
            $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline
        Start-Sleep -Seconds 1
    }
    Assert-NewPaperVerifiedSnapshot $targetPaperService $targetPaperService.StdoutPath $playerName `
        (Get-SecondsUntilDeadline $earliestAssertionExpiry 3 `
            'FABRIC_FEDERATION_GUI_PRE_EXPIRY_LOCAL_STATE_PROOF_LATE')
    $preExpiryStatusCutoff = $earliestAssertionExpiry.AddSeconds(-2)
    while ([DateTimeOffset]::UtcNow -lt $preExpiryStatusCutoff) {
        Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
            $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline
        $preExpiryOneBaseline = Get-FileRegexCount $targetService.StdoutPath $targetOnePattern
        Send-ServiceCommand $targetService 'mcacefederation status'
        Wait-NewFileRegex $targetService $targetService.StdoutPath $targetOnePattern $preExpiryOneBaseline `
            (Get-SecondsUntilDeadline $earliestAssertionExpiry 2 `
                'FABRIC_FEDERATION_GUI_PRE_EXPIRY_OBSERVATION_PROOF_LATE')
        if ([DateTimeOffset]::UtcNow -ge $earliestAssertionExpiry) {
            throw 'FABRIC_FEDERATION_GUI_PRE_EXPIRY_OBSERVATION_PROOF_LATE'
        }
        $targetObservationOneBeforeExpiry = $true
        Start-Sleep -Seconds 1
    }
    if (-not $targetObservationOneBeforeExpiry) {
        throw 'FABRIC_FEDERATION_GUI_PRE_EXPIRY_OBSERVATION_PROOF_MISSING'
    }
    Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
        $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline

    # The initial readiness observations=0 line is excluded by a baseline count. A new zero is
    # accepted only after the lower-bound expiry and while the exact target session remains live.
    $targetZeroPattern = 'MCAce: federation enabled=true configured=true audit=HEALTHY ' +
        'audit_backlog=0 audit_committed=[0-9]+ audit_failures=0 local=mcace-target peers=1 pending=0 observations=0'
    $targetZeroBaseline = Get-FileRegexCount $targetService.StdoutPath $targetZeroPattern
    $notBefore = $latestAssertionExpiry.AddSeconds(2)
    while ([DateTimeOffset]::UtcNow -lt $notBefore) {
        Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
            $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline
        Start-Sleep -Seconds 1
    }
    $expiryDeadline = $latestAssertionExpiry.AddSeconds(30)
    while ([DateTimeOffset]::UtcNow -lt $expiryDeadline -and
            (Get-FileRegexCount $targetService.StdoutPath $targetZeroPattern) -le $targetZeroBaseline) {
        Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
            $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline
        Send-ServiceCommand $targetService 'mcacefederation status'
        Start-Sleep -Seconds 2
    }
    if ((Get-FileRegexCount $targetService.StdoutPath $targetZeroPattern) -le $targetZeroBaseline) {
        throw 'FABRIC_FEDERATION_GUI_TARGET_OBSERVATION_DID_NOT_EXPIRE'
    }
    $observationExpired = $true
    $targetObservationZero = $true
    Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
        $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline
    Assert-NewPaperVerifiedSnapshot $targetPaperService $targetPaperService.StdoutPath $playerName 10
    Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
        $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline
    $localStateUnchanged = $targetPaperAdmissionVerified
    $targetSessionConnectedThroughExpiry = $true

    Stop-JavaService $fabricClient ''
    $fabricClient = $null
    $clientShutdownCompleted = $true
    $runtimeAssertionsComplete = $true
} catch {
    $failure = $_
} finally {
    foreach ($cleanup in @(
            @('fabric', $fabricClient, ''),
            @('target-paper', $targetPaperService, 'stop'),
            @('source-paper', $sourcePaperService, 'stop'),
            @('target-proxy', $targetService, 'end'),
            @('source-proxy', $sourceService, 'end'))) {
        try {
            if ($cleanup[0] -ceq 'fabric') {
                Stop-JavaService $cleanup[1] $cleanup[2]
            } else {
                Stop-FederationJavaService $cleanup[1] $cleanup[2]
            }
        } catch {
            if ($null -eq $failure) { $failure = $_ }
        }
    }
    try { Stop-RunTokenJavaProcesses $runToken }
    catch { if ($null -eq $failure) { $failure = $_ } }
}

$remainingOwnedProcessCount = -1
$cleanupPortsFree = $false
try {
    $remainingOwnedProcessCount = @(Get-RunTokenJavaProcesses $runToken).Count
    $cleanupPortsFree = @($allPorts | Where-Object { -not (Test-LoopbackPortFree $_) }).Count -eq 0
    if ($remainingOwnedProcessCount -ne 0 -or -not $cleanupPortsFree) {
        throw 'FABRIC_FEDERATION_GUI_ZERO_PROCESS_AND_PORT_RESIDUE_REQUIRED'
    }
    if ($null -eq $runLocalBefore) {
        throw 'FABRIC_FEDERATION_GUI_RUN_LOCAL_PRESTART_BINDING_REQUIRED'
    }
    $runLocalAfter = Get-RunLocalRuntimeBinding `
        $sourceRuntime $targetRuntime $sourcePaperRuntime $targetPaperRuntime
    Assert-RunLocalRuntimeBinding $runLocalAfter $currentBinding
    Assert-BindingUnchanged $runLocalBefore $runLocalAfter `
        'FABRIC_FEDERATION_GUI_RUN_LOCAL_INPUT_CHANGED'
    $postRunInput = Get-ImmutableInputBinding
    Assert-BindingUnchanged $preBuildInput $postRunInput `
        'FABRIC_FEDERATION_GUI_IMMUTABLE_INPUT_CHANGED_DURING_RUN'
    $currentAfterRun = Get-CurrentBinding
    Assert-BindingUnchanged $currentBinding $currentAfterRun `
        'FABRIC_FEDERATION_GUI_CURRENT_BINDING_CHANGED_DURING_RUN'
} catch {
    if ($null -eq $failure) { $failure = $_ }
}

if ($null -ne $failure -or -not $runtimeAssertionsComplete -or -not $clientShutdownCompleted) {
    $message = if ($null -ne $failure) { $failure.Exception.Message } else {
        'real Fabric federation GUI assertions did not reach the commit boundary'
    }
    if ($runRootCreated) { Remove-OwnedRunDirectory $runRoot }
    throw "FABRIC_FEDERATION_GUI_HANDOFF_FAILED: $message"
}

$report = [ordered]@{
    schema = $reportSchema
    generated_at = [DateTimeOffset]::UtcNow.ToString('o')
    source_mode = 'EXECUTED_REAL_FABRIC_GUI'
    status = 'passed'
    artifact_class = $artifactClass
    fabric_target = $FabricTarget
    minecraft_version = [string]$fabricDescriptor.minecraft_version
    fabric_api_version = [string]$fabricDescriptor.fabric_api_version
    fabric_artifact_kind = [string]$fabricDescriptor.artifact_kind
    fabric_java_major = [int]$fabricDescriptor.java_major
    fabric_runtime_mode = $fabricRuntimeMode
    fabric_build_id = [string]$currentBinding.fabric_build_id
    fabric_codesource_sha256_observed = [string]$currentBinding.fabric_artifact_sha256
    source_proxy = $SourceProxy
    target_proxy = $TargetProxy
    federation_assertion_ttl_seconds = $FederationAssertionTtlSeconds
    operator_human_attestation_count = 1
    human_visible_federation_consent_count = 1
    no_gui_automation = $true
    raw_peer_evidence_used = $false
    raw_content_retained = $false
    fabric_artifact_mode_verified = $true
    source_local_auth_verified = $sourceLocalAuthVerified
    source_paper_admission_verified = $sourcePaperAdmissionVerified
    enablement_consent_requested = $true
    enablement_consent_rendered = $true
    enablement_consent_accepted = $true
    source_export_consent_inherited = $true
    source_grant_stored_memory_only = $true
    source_grant_ready_observed = $sourceGrantReadyObserved
    source_disconnected_before_target_auth = $sourceDisconnectedBeforeTargetAuth
    target_local_auth_verified = $targetLocalAuthVerified
    target_import_consent_inherited = $true
    presentation_sent = $presentationSent
    target_observation_recorded = $targetObservationRecorded
    target_subject_bound = $targetSubjectBound
    target_observation_status_count_one = $targetObservationCountOne
    target_observation_status_one_before_expiry = $targetObservationOneBeforeExpiry
    target_paper_admission_verified = $targetPaperAdmissionVerified
    local_trust_risk_admission_unchanged = $localStateUnchanged
    target_session_connected_through_expiry = $targetSessionConnectedThroughExpiry
    observation_expired = $observationExpired
    target_observation_status_zero_after_expiry = $targetObservationZero
    client_shutdown_completed = $clientShutdownCompleted
    cleanup_ports_free = $cleanupPortsFree
    remaining_owned_process_count = $remainingOwnedProcessCount
    passed = $true
}
try {
    # Delete every mutable runtime artifact before the first passing report byte is created. The
    # commit file is still written last, and any partial/invalid triplet is removed fail closed.
    Clear-OwnedRunForEvidence $runRoot
    $reportPath = Write-EvidenceTriplet $runRoot $report $currentBinding
    $null = Assert-EvidenceTriplet $reportPath $currentBinding $SourceProxy $TargetProxy
} catch {
    if ($runRootCreated) { Remove-OwnedRunDirectory $runRoot }
    throw
}
Write-Output "FABRIC_FEDERATION_GUI_HANDOFF_PASS|$runRoot"
