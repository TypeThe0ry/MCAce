[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

$target = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'platform-load-smoke.ps1'))
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $target, [ref]$tokens, [ref]$parseErrors)
Assert-True ($parseErrors.Count -eq 0) 'platform-load-smoke.ps1 has PowerShell parse errors'

$treeSelector = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-SmokeProcessTreeTargets'
}, $true)
$treeStopper = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Stop-SmokeProcessTree'
}, $true)
$serviceStopper = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Stop-JavaService'
}, $true)
$runTokenStopper = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Stop-RunTokenJavaProcesses'
}, $true)
$runTokenValidator = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Assert-SmokeRunToken'
}, $true)
$runTokenMatcher = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Test-ExactRunTokenArgument'
}, $true)
Assert-True ($null -ne $treeSelector) 'marker-constrained process-tree target selector is missing'
Assert-True ($null -ne $treeStopper) 'marker-constrained process-tree stopper is missing'
Assert-True ($null -ne $serviceStopper) 'Java service stopper is missing'
Assert-True ($null -ne $runTokenStopper) 'global run-token Java stopper is missing'
Assert-True ($null -ne $runTokenValidator) 'CSPRNG run-token validator is missing'
Assert-True ($null -ne $runTokenMatcher) 'exact run-token JVM-argument matcher is missing'

$killCalls = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
        $node.Member.Extent.Text -eq 'Kill'
}, $true))
$parameterizedKillCalls = @($killCalls | Where-Object { $null -ne $_.Arguments })
Assert-True ($parameterizedKillCalls.Count -eq 0) `
    'platform smoke must not depend on Process.Kill(Boolean) or any parameterized Kill overload'
$rootKillCalls = @($serviceStopper.Body.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
        $node.Member.Extent.Text -eq 'Kill' -and
        $node.Expression.Extent.Text -eq '$process' -and
        $null -eq $node.Arguments
}, $true))
Assert-True ($rootKillCalls.Count -eq 1) `
    "expected one parameterless exact-root process kill, found $($rootKillCalls.Count)"

$treeCleanupCalls = @($serviceStopper.Body.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Stop-SmokeProcessTree'
}, $true))
Assert-True ($treeCleanupCalls.Count -eq 2) `
    "expected pre-root and final marker-constrained child cleanup, found $($treeCleanupCalls.Count) calls"
foreach ($call in $treeCleanupCalls) {
    Assert-True ($call.Extent.Text -eq 'Stop-SmokeProcessTree $rootPid $Service.RunToken') `
        "process-tree cleanup lost its exact root/run-token arguments: $($call.Extent.Text)"
}
Assert-True (@($treeCleanupCalls | Where-Object {
            $_.Extent.EndOffset -lt $rootKillCalls[0].Extent.StartOffset
        }).Count -eq 1) `
    'marker-constrained descendants must be enumerated before the exact root is killed'

$stopProcessCalls = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Stop-Process'
}, $true))
$treeStopProcessCalls = @($treeStopper.Body.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Stop-Process'
}, $true))
$runTokenStopProcessCalls = @($runTokenStopper.Body.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Stop-Process'
}, $true))
Assert-True ($stopProcessCalls.Count -eq 2 -and $treeStopProcessCalls.Count -eq 1 -and
        $runTokenStopProcessCalls.Count -eq 1) `
    'PID-based forced stops must remain inside the tree or unique run-token stoppers'

$selectorText = $treeSelector.Extent.Text
foreach ($requiredCleanupBoundary in @(
        'Assert-SmokeRunToken $RunToken',
        '$child.Name -in @(''java.exe'', ''javaw.exe'')',
        'Test-ExactRunTokenArgument ([string]$child.CommandLine) $RunToken')) {
    Assert-True ($selectorText.IndexOf($requiredCleanupBoundary, [StringComparison]::Ordinal) -ge 0) `
        "process-tree selector lost cleanup boundary: $requiredCleanupBoundary"
}

# Execute only the pure target selector against synthetic process metadata. This proves that
# exact-token Java descendants are selected through unmarked intermediaries while substring-only,
# adjacent-token, unmarked, non-Java, and non-descendant processes remain outside the kill set.
Invoke-Expression $runTokenValidator.Extent.Text
Invoke-Expression $runTokenMatcher.Extent.Text
Invoke-Expression $treeSelector.Extent.Text
$logicToken = '0123456789abcdef0123456789abcdef'
$logicArgument = "-Dmcace.smoke.run-token=$logicToken"
$logicRunId = '20260813T123456789Z'
$logicSnapshot = @(
    [pscustomobject]@{ ProcessId = 101; ParentProcessId = 100; Name = 'java.exe'; CommandLine = "java $logicArgument -jar owned.jar" },
    [pscustomobject]@{ ProcessId = 102; ParentProcessId = 100; Name = 'java.exe'; CommandLine = "java -Drun.id=$logicRunId -jar unrelated.jar" },
    [pscustomobject]@{ ProcessId = 103; ParentProcessId = 102; Name = 'java.exe'; CommandLine = "java `"$logicArgument`" -jar owned.jar" },
    [pscustomobject]@{ ProcessId = 104; ParentProcessId = 100; Name = 'cmd.exe'; CommandLine = "cmd /c $logicRunId" },
    [pscustomobject]@{ ProcessId = 105; ParentProcessId = 104; Name = 'java.exe'; CommandLine = "java $logicArgument -jar owned.jar" },
    [pscustomobject]@{ ProcessId = 106; ParentProcessId = 100; Name = 'javaw.exe'; CommandLine = "javaw $logicArgument -jar owned.jar" },
    [pscustomobject]@{ ProcessId = 107; ParentProcessId = 100; Name = 'java.exe'; CommandLine = "java $($logicArgument)0 -jar unrelated.jar" },
    [pscustomobject]@{ ProcessId = 108; ParentProcessId = 100; Name = 'java.exe'; CommandLine = "java x$logicArgument -jar unrelated.jar" },
    [pscustomobject]@{ ProcessId = 109; ParentProcessId = 100; Name = 'java.exe'; CommandLine = "java `"$logicArgument`"suffix -jar unrelated.jar" },
    [pscustomobject]@{ ProcessId = 200; ParentProcessId = 999; Name = 'java.exe'; CommandLine = "java $logicArgument -jar owned.jar" }
)
$logicTargets = @(Get-SmokeProcessTreeTargets $logicSnapshot 100 $logicToken | Sort-Object)
Assert-True (($logicTargets -join ',') -eq '101,103,105,106') `
    "run-token process selection drifted: $($logicTargets -join ',')"
Assert-True (Test-ExactRunTokenArgument "java $logicArgument -jar owned.jar" $logicToken) `
    'exact unquoted run-token JVM argument was rejected'
Assert-True (Test-ExactRunTokenArgument "java `"$logicArgument`" -jar owned.jar" $logicToken) `
    'exact quoted run-token JVM argument was rejected'
foreach ($nonOwner in @(
        "java -Drun.id=$logicRunId -jar unrelated.jar",
        "java $($logicArgument)0 -jar unrelated.jar",
        "java x$logicArgument -jar unrelated.jar",
        "java `"$logicArgument`"suffix -jar unrelated.jar")) {
    Assert-True (-not (Test-ExactRunTokenArgument $nonOwner $logicToken)) `
        "substring or adjacent run-token text was accepted as ownership: $nonOwner"
}
$invalidTokenRejected = $false
try {
    @(Get-SmokeProcessTreeTargets $logicSnapshot 100 $logicRunId) | Out-Null
} catch {
    $invalidTokenRejected = $true
}
Assert-True $invalidTokenRejected 'process-tree selector accepted a timestamp instead of a 128-bit run token'

$parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object {
    $_.Name.VariablePath.UserPath
})
Assert-True ($parameterNames -contains 'RetainDiagnostics') 'RetainDiagnostics switch is missing'
Assert-True ($parameterNames -contains 'ReportOnly') 'ReportOnly switch is missing'
Assert-True ($parameterNames -contains 'MaximumReportAgeMinutes') 'report freshness parameter is missing'
Assert-True ($parameterNames -contains 'FabricTarget') 'explicit FabricTarget selector is missing'
foreach ($name in @('ExpectedFabricArtifactSha256', 'ExpectedVelocityPluginSha256',
        'ExpectedPaperPluginSha256', 'ExpectedVelocityServerSha256',
        'ExpectedPaperServerSha256', 'ExpectedPaperPreparedManifestSha256',
        'ExpectedPaperPreparedTreeSha256', 'ExpectedFabricVersionInfoSha256',
        'ExpectedFabricAssetIndexSha256', 'ExpectedFabricAssetObjectManifestSha256')) {
    Assert-True ($parameterNames -contains $name) "ReportOnly expected product hash is missing: $name"
}

$builder = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'New-SanitizedReleaseReport'
}, $true)
Assert-True ($null -ne $builder) 'sanitized release report builder is missing'
$reportTable = $builder.Body.Find({
    param($node)
    $node -is [System.Management.Automation.Language.HashtableAst]
}, $true)
Assert-True ($null -ne $reportTable) 'sanitized release report hashtable is missing'

$actualKeys = @($reportTable.KeyValuePairs | ForEach-Object {
    $_.Item1.Extent.Text.Trim("'", '"')
})
$expectedKeys = @(
    'schema',
    'generated_at',
    'artifact_class',
    'status',
    'release_evidence',
    'diagnostics_retained',
    'fabric_target',
    'minecraft_version',
    'velocity_policy_minecraft_versions',
    'velocity_policy_client_build_ids',
    'fabric_api_version',
    'fabric_artifact_kind',
    'fabric_java_major',
    'fabric_runtime_mode',
    'fabric_runtime_jar_loaded',
    'fabric_release_jar_loaded',
    'fabric_client_requested',
    'fabric_evidence_requested',
    'enablement_consent_requested',
    'enablement_consent_rendered',
    'enablement_consent_accepted',
    'explicit_file_fixture_present',
    'explicit_file_manifest_entries',
    'explicit_file_manifest_entries_observed',
    'explicit_file_consent_requested',
    'explicit_file_consent_rendered',
    'explicit_file_consent_accepted',
    'fabric_authenticated',
    'game_render_frame_requested',
    'game_render_frame_consent_rendered',
    'game_render_frame_consent_allowed',
    'game_render_frame_consent_inherited',
    'game_render_frame_completed',
    'fabric_gui_coverage',
    'fabric_evidence_coverage',
    'raw_evidence_retained',
    'evidence_audit_summary_observed',
    'persistent_identity_unchanged',
    'velocity_transport_classes_present',
    'paper_admission_channel_enabled',
    'paper_missing_pin_failure_observed',
    'paper_missing_pin_plugin_disabled',
    'paper_missing_pin_channel_absent',
    'loopback_listener_count',
    'assertion_count',
    'cleanup_completed',
    'cleanup_ports_free',
    'remaining_owned_process_count'
)
Assert-True (($actualKeys -join '|') -eq ($expectedKeys -join '|')) `
    "sanitized report schema drifted: $($actualKeys -join ', ')"

$forbiddenKeyPattern = '(?i)((^|_)(path|hash|sha256|uuid|operator|player|request_id|run_id|timestamp|port|pid|address|log)($|_)|audit_summary$)'
$forbiddenKeys = @($actualKeys | Where-Object { $_ -match $forbiddenKeyPattern })
Assert-True ($forbiddenKeys.Count -eq 0) `
    "sanitized report contains identifying or diagnostic keys: $($forbiddenKeys -join ', ')"
$builderText = $builder.Extent.Text
foreach ($forbiddenValue in @('$runRoot', '$runId', '$runToken', 'Get-Sha256', '$auditLine',
        '$FabricEvidencePlayerName')) {
    Assert-True ($builderText.IndexOf($forbiddenValue, [StringComparison]::Ordinal) -lt 0) `
        "sanitized report references forbidden diagnostic value $forbiddenValue"
}

$bindingBuilder = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'New-EvidenceBinding'
}, $true)
Assert-True ($null -ne $bindingBuilder) 'evidence binding builder is missing'
$bindingTable = $bindingBuilder.Body.Find({
    param($node)
    $node -is [System.Management.Automation.Language.HashtableAst]
}, $true)
Assert-True ($null -ne $bindingTable) 'evidence binding hashtable is missing'
$actualBindingKeys = @($bindingTable.KeyValuePairs | ForEach-Object {
    $_.Item1.Extent.Text.Trim("'", '"')
})
$expectedBindingKeys = @(
    'schema', 'report_schema', 'report_generated_at', 'report_sha256', 'source_mode',
    'fabric_target', 'minecraft_version', 'velocity_policy_minecraft_versions',
    'velocity_policy_client_build_ids', 'fabric_api_version', 'fabric_artifact_kind',
    'fabric_java_major', 'fabric_runtime_mode', 'fabric_runtime_jar_loaded',
    'fabric_release_jar_loaded', 'fabric_artifact_marker_observed', 'fabric_build_id', 'script_sha256',
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
    'gradle_launcher_sha256', 'gradle_core_sha256', 'passed'
)
Assert-True (($actualBindingKeys -join '|') -eq ($expectedBindingKeys -join '|')) `
    "evidence binding V5 schema drifted: $($actualBindingKeys -join ', ')"

$rawLogCopies = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Copy-Item' -and
        $node.Extent.Text -match '\$(fabricLog|paperLog|evidenceAudit)\b'
}, $true))
Assert-True ($rawLogCopies.Count -eq 4) `
    "expected four explicitly guarded raw-log copies, found $($rawLogCopies.Count)"
foreach ($copy in $rawLogCopies) {
    $parent = $copy.Parent
    $guarded = $false
    while ($null -ne $parent -and $parent -ne $ast) {
        if ($parent -is [System.Management.Automation.Language.IfStatementAst] -and
                @($parent.Clauses | Where-Object {
                    $_.Item1.Extent.Text -match '\$RetainDiagnostics\b'
                }).Count -gt 0) {
            $guarded = $true
            break
        }
        $parent = $parent.Parent
    }
    Assert-True $guarded "raw-log copy is not guarded by RetainDiagnostics: $($copy.Extent.Text)"
}

$source = [System.IO.File]::ReadAllText($target)
foreach ($required in @(
        "[ValidateSet('1.21.11', '26.1.2', '26.2')]",
        '$fabricDescriptor = $fabricTargets[$FabricTarget]',
        "Join-Path `$fabricRoot 'options.txt'",
        '"fov:0.5`nrenderDistance:8`n"',
        'Test-Path -LiteralPath $explicitFileFixture -PathType Leaf',
        '(Get-Item -LiteralPath $explicitFileFixture).Length -gt 0',
        'MCAce explicit-file manifest prepared entries=1',
        'explicit_file_manifest_entries_observed',
        "`$fabricArtifactClass = 'sanitized-final-fabric-gui-evidence'",
        'artifact_class = $fabricArtifactClass',
        'release_evidence = $false',
        "artifact_class = 'diagnostic-non-release'",
        'release_evidence = $false',
        'diagnostics_retained = [bool]$RetainDiagnostics',
        "fabric_runtime_mode = `$fabricRuntimeMode",
        'fabric_release_jar_loaded = $FabricReleaseJarLoaded',
        "`$reportSchema = 8",
        "runtime_mode = 'LOOM_FINAL_REMAP_ARTIFACT'",
        "runtime_mode = 'LOOM_FINAL_NAMED_JAR_ARTIFACT'",
        "artifact_kind = 'FINAL_REMAP_JAR'",
        "artifact_kind = 'FINAL_NAMED_JAR'",
        "paper_build = '132'",
        "paper_build = '74'",
        "paper_build = '116'",
        '$fabricSmokeBuildId = "platform-smoke-$runId"',
        '"MCACE_FABRIC_ARTIFACT_LOADED version=$fabricArtifactVersion build_id=$fabricSmokeBuildId"',
        '" code_source_sha256=$($currentEvidenceBinding.fabric_runtime_artifact_sha256)"',
        '"-PmcaceClientBuildId=$fabricSmokeBuildId"',
        '"-PmcaceSmokeExpectedArtifactSha256=$ExpectedArtifactSha256"',
        '"-PmcaceSmokeRunToken=$runToken"',
        '$runTokenJvmArgument = "-Dmcace.smoke.run-token=$runToken"',
        'function New-SmokeRunToken',
        '[System.Security.Cryptography.RandomNumberGenerator]::Create()',
        'function Test-ExactRunTokenArgument',
        "'-PmcaceSmokeArtifactMode=true'",
        'function Assert-FabricArtifactMarker',
        'function Assert-FabricAssetCache',
        'PLATFORM_SMOKE_FABRIC_ASSET_INDEX_CACHE_REQUIRED',
        'PLATFORM_SMOKE_FABRIC_ASSET_OBJECT_CACHE_REQUIRED',
        'fabric_build_id = $Current.fabric_build_id',
        'velocity_policy_minecraft_versions = $Current.velocity_policy_minecraft_versions',
        'velocity_policy_client_build_ids = $Current.velocity_policy_client_build_ids',
        'fabric_artifact_marker_observed = [bool]$Report.fabric_runtime_jar_loaded',
        "`$bindingSchema = 'MCACE_FABRIC_GUI_EVIDENCE_BINDING_V6'",
        'function Set-ExactVelocityPolicyTuple',
        "'policy.minecraft-versions' = `$MinecraftVersion",
        "'policy.client-build-ids' = `$ClientBuildId",
        'PLATFORM_SMOKE_VELOCITY_POLICY_KEY_COUNT_INVALID',
        'PLATFORM_SMOKE_VELOCITY_POLICY_READBACK_COUNT_INVALID',
        'PLATFORM_SMOKE_VELOCITY_POLICY_READBACK_VALUE_INVALID',
        '$velocityPolicyTuple = Set-ExactVelocityPolicyTuple',
        '$velocityHandshakeTimeoutSeconds = [Math]::Min(30, $manualConsentHandshakeTimeoutSeconds)',
        'handshake.timeout.seconds=$velocityHandshakeTimeoutSeconds',
        'manual_consent_handshake_timeout_seconds = $manualConsentHandshakeTimeoutSeconds',
        'velocity_policy_minecraft_versions = [string]$VelocityPolicyTuple',
        'velocity_policy_client_build_ids = [string]$VelocityPolicyTuple',
        "`$current['velocity_policy_minecraft_versions'] = [string]`$fabricDescriptor.minecraft_version",
        "`$current['velocity_policy_client_build_ids'] = `$fabricIdentity.build_id",
        'function Assert-EvidencePair',
        'function Assert-PassingReportRaw',
        'function Assert-BindingRaw',
        'report_sha256 = Get-BytesSha256 $ReportBytes',
        'fabric_target = $Current.fabric_target',
        'minecraft_version = $Current.minecraft_version',
        'fabric_api_version = $Current.fabric_api_version',
        'fabric_artifact_kind = $Current.fabric_artifact_kind',
        'fabric_java_major = [int]$Current.fabric_java_major',
        'source_manifest_sha256',
        'fabric_artifact_sha256',
        'velocity_plugin_sha256',
        'paper_plugin_sha256',
        'velocity_server_sha256',
        'paper_server_sha256',
        'server_matrix_manifest_sha256',
        'paper_prepared_manifest_sha256',
        'paper_prepared_tree_sha256',
        'fabric_version_info_sha1',
        'fabric_version_info_sha256',
        'fabric_asset_index_sha1',
        'fabric_asset_index_sha256',
        'fabric_asset_object_manifest_sha256',
        'root_java_executable_sha256',
        'target_java_executable_sha256',
        "'fabric-modern'",
        "'gradle\verification-metadata.xml'",
        "'client-26.1.2\gradle.lockfile'",
        "'client-26.2\gradle.lockfile'",
        '$summary.fabric_target -ceq $FabricTarget',
        "`$gradleVersion = '9.6.1'",
        'function Invoke-PinnedOfflineGradle',
        "':stageModernFabricDeps'",
        'PLATFORM_SMOKE_ROOT_JDK21_BUILD_FAILED',
        'PLATFORM_SMOKE_MODERN_JDK25_BUILD_FAILED',
        'PLATFORM_SMOKE_FABRIC_ARTIFACT_VERIFY_FAILED',
        'Resolve-RootJava21',
        'Resolve-TargetJava',
        'MCACE_JAVA25_HOME',
        "'org.gradle.launcher.GradleMain'",
        "'--offline'",
        "'--dependency-verification=strict'",
        "'--no-build-cache'",
        "'--no-configuration-cache'",
        "'--no-daemon'",
        "'--no-parallel'",
        "'--max-workers=1'",
        'MCACE_SERVER_VERSION_MATRIX_ASSETS_V1',
        "'paper\{0}\{1}' -f `$FabricTarget, [string]`$fabricDescriptor.paper_build",
        'PLATFORM_SMOKE_PINNED_CACHE_REQUIRED',
        'PLATFORM_SMOKE_EXACT_${Role}_JAVA_${Major}_REQUIRED',
        '$ExpectedFabricArtifactSha256.ToLowerInvariant()',
        '$ExpectedVelocityPluginSha256.ToLowerInvariant()',
        '$ExpectedPaperPluginSha256.ToLowerInvariant()',
        '$ExpectedVelocityServerSha256.ToLowerInvariant()',
        '$ExpectedPaperServerSha256.ToLowerInvariant()',
        '$ExpectedPaperPreparedManifestSha256.ToLowerInvariant()',
        '$ExpectedPaperPreparedTreeSha256.ToLowerInvariant()',
        '$ExpectedFabricVersionInfoSha256.ToLowerInvariant()',
        '$ExpectedFabricAssetIndexSha256.ToLowerInvariant()',
        '$ExpectedFabricAssetObjectManifestSha256.ToLowerInvariant()',
        'PLATFORM_SMOKE_REPORT_ONLY_EXPECTED_PRODUCT_HASH_MISMATCH',
        'Stop-RunTokenJavaProcesses $runToken',
        'Get-RunTokenJavaProcesses $runToken',
        'remaining_owned_process_count = $remainingOwnedProcessCount',
        'function Assert-SmokeRunLeaf',
        'function Initialize-SafeOwnedDirectory',
        'function New-ExclusiveOwnedDirectory',
        'function Assert-OwnedTreeNoReparse',
        "`$buildRoot = Join-Path `$repoRoot 'build'",
        "`$smokeRoot = Join-Path `$buildRoot 'platform-smoke'",
        '$buildRoot = Initialize-SafeOwnedDirectory $buildRoot $repoRoot',
        '$smokeRoot = Initialize-SafeOwnedDirectory $smokeRoot $buildRoot',
        "'MCACE_SERVER_VERSION_MATRIX_PREPARED_V1'",
        "((@(`$manifest.roots) -join ',') -cne 'cache,libraries,versions')",
        '@($manifest.trees).Count -ne 6',
        'Get-PreparedTreeBinding $preparedPaperRoot',
        'paper_prepared_manifest_sha256 = $prepared.manifest_sha256',
        'paper_prepared_tree_sha256 = $prepared.tree_sha256',
        '$executedScriptSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256)',
        '$preBuildInputSnapshot = Get-ImmutableInputSnapshot',
        'Assert-BindingSnapshotUnchanged $preBuildInputSnapshot $currentEvidenceBinding',
        '$runLocalRuntimeBinding = Get-RunLocalRuntimeBinding',
        'Assert-RunLocalRuntimeBinding $runLocalRuntimeBinding $currentEvidenceBinding',
        '$runLocalAfterRun = Get-RunLocalRuntimeBinding',
        'Assert-BindingSnapshotUnchanged $runLocalRuntimeBinding $runLocalAfterRun',
        'Assert-BindingSnapshotUnchanged $preBuildInputSnapshot $currentAfterRun',
        'Assert-BindingSnapshotUnchanged $currentEvidenceBinding $currentAfterRun',
        '$allowedRoot = Assert-DirectLocalPath $runsRoot -Directory',
        '$resolvedRun = Assert-OwnedTreeNoReparse $RunDirectory',
        "'report.json', [StringComparison]::OrdinalIgnoreCase",
        'Remove-UnretainedDiagnostics $runRoot $reportPath')) {
    Assert-True ($source.IndexOf($required, [StringComparison]::Ordinal) -ge 0) `
        "missing privacy archive boundary: $required"
}

foreach ($forbidden in @('Invoke-WebRequest', 'Invoke-RestMethod',
        'org.gradle.wrapper.GradleWrapperMain', "Join-Path `$repoRoot 'gradlew.bat'",
        'Get-RunMarkerJavaProcesses', 'Stop-RunMarkerJavaProcesses',
        'MCACE_FABRIC_GUI_EVIDENCE_BINDING_V3', '$reportSchema = 5')) {
    Assert-True ($source.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -lt 0) `
        "platform smoke retained a forbidden online/wrapper path: $forbidden"
}
Assert-True ($source -notmatch '(?m)^\s*run_token\s*=') `
    'a report or binding hashtable exposes the private process-ownership run token'

$diagnosticCleanupCalls = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Remove-UnretainedDiagnostics'
}, $true))
Assert-True ($diagnosticCleanupCalls.Count -eq 2) `
    "both success and failure must remove unretained diagnostics; found $($diagnosticCleanupCalls.Count) calls"

function Get-TargetFunctionAst([string]$Name) {
    return $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $Name
    }, $true)
}

# Lock the three reviewed target identities.  These values are the immutable Mojang
# version-info and asset-index identities consumed by Assert-FabricAssetCache; the
# per-object manifest is then derived from every unique, SHA-1-verified cache object.
$fabricTargetsAssignment = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$fabricTargets'
}, $true)
Assert-True ($null -ne $fabricTargetsAssignment) 'Fabric target identity table is missing'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Invoke-Expression $fabricTargetsAssignment.Extent.Text
$expectedTargetPins = [ordered]@{
    '1.21.11' = [ordered]@{
        java_major = 21
        asset_index = '29'
        version_info_sha1 = '4b5fd518c8f06ea3f9fdef2895f729c204f0bf5e'
        version_info_sha256 = 'f6ce577abd648a59766f2236dcaa76b5a3817a8122fc704713976f5cc6895962'
        asset_index_sha1 = '34c7bef563edad4d5e3ae8157e904690afb1fa50'
        asset_index_size = 529966L
    }
    '26.1.2' = [ordered]@{
        java_major = 25
        asset_index = '30'
        version_info_sha1 = 'edcfd100a4856650b6e9797bac8f7fd76821979e'
        version_info_sha256 = '92dc2a84d8151cf8ff26b4be4c0b1d3b9e88f0c28a860e1cae1a5b3fbdefee9a'
        asset_index_sha1 = 'aa83698cef26e50089d85218e55bd402f38c7821'
        asset_index_size = 548391L
    }
    '26.2' = [ordered]@{
        java_major = 25
        asset_index = '32'
        version_info_sha1 = 'dc69be58cf16ad99f4b1ae7360c9a29c8c819ca5'
        version_info_sha256 = 'd4a21bea5568a8e194ff8fc94081489cf2b694a9d04c7bc4e673add58a10955f'
        asset_index_sha1 = 'cf75b185cb35b32e299b0c8e674fa202d7911a3c'
        asset_index_size = 586366L
    }
}
Assert-True (($fabricTargets.Keys -join '|') -ceq ($expectedTargetPins.Keys -join '|')) `
    'Fabric target identity set or order drifted'
foreach ($targetName in @($expectedTargetPins.Keys)) {
    foreach ($field in @($expectedTargetPins[$targetName].Keys)) {
        Assert-True ([string]$fabricTargets[$targetName][$field] -ceq
            [string]$expectedTargetPins[$targetName][$field]) `
            "Fabric target pin drifted: $targetName/$field"
    }
}
Assert-True (@($fabricTargets.Values.version_info_sha1 | Sort-Object -Unique).Count -eq 3) `
    'each Fabric target must pin a unique version-info SHA-1'
Assert-True (@($fabricTargets.Values.version_info_sha256 | Sort-Object -Unique).Count -eq 3) `
    'each Fabric target must pin a unique version-info SHA-256'
Assert-True (@($fabricTargets.Values.asset_index_sha1 | Sort-Object -Unique).Count -eq 3) `
    'each Fabric target must pin a unique asset-index SHA-1'

# Prove ordering rather than merely proving that the closure tokens exist somewhere.
$scriptHashOffset = $source.IndexOf('$executedScriptSha256 = (Get-FileHash', [StringComparison]::Ordinal)
$targetTableOffset = $source.IndexOf('$fabricTargets = [ordered]@{', [StringComparison]::Ordinal)
$preBuildOffset = $source.IndexOf('$preBuildInputSnapshot = Get-ImmutableInputSnapshot', [StringComparison]::Ordinal)
$firstBuildOffset = $source.IndexOf(
    'Invoke-PinnedOfflineGradle $script:RootJavaPath', [StringComparison]::Ordinal)
$postBuildOffset = $source.IndexOf(
    'Assert-BindingSnapshotUnchanged $preBuildInputSnapshot $currentEvidenceBinding',
    [StringComparison]::Ordinal)
$preStartRunLocalOffset = $source.IndexOf(
    '$runLocalRuntimeBinding = Get-RunLocalRuntimeBinding', [StringComparison]::Ordinal)
$firstStartOffset = $source.IndexOf(
    "`$velocity = Start-JavaService 'velocity'", [StringComparison]::Ordinal)
$policyTupleOffset = $source.IndexOf(
    '$velocityPolicyTuple = Set-ExactVelocityPolicyTuple', [StringComparison]::Ordinal)
$velocityRestartOffset = $source.IndexOf(
    "`$velocity = Start-JavaService 'velocity-restart'", [StringComparison]::Ordinal)
$afterRunOffset = $source.IndexOf(
    '$runLocalAfterRun = Get-RunLocalRuntimeBinding', [StringComparison]::Ordinal)
$finalSourceOffset = $source.IndexOf(
    'Assert-BindingSnapshotUnchanged $preBuildInputSnapshot $currentAfterRun',
    [StringComparison]::Ordinal)
$buildRootInitOffset = $source.IndexOf(
    '$buildRoot = Initialize-SafeOwnedDirectory $buildRoot $repoRoot',
    [StringComparison]::Ordinal)
$smokeRootInitOffset = $source.IndexOf(
    '$smokeRoot = Initialize-SafeOwnedDirectory $smokeRoot $buildRoot',
    [StringComparison]::Ordinal)
$runsRootInitOffset = $source.IndexOf(
    '$runsRoot = Initialize-SafeOwnedDirectory $runsRoot $smokeRoot',
    [StringComparison]::Ordinal)
Assert-True ($scriptHashOffset -ge 0 -and $scriptHashOffset -lt $targetTableOffset) `
    'executed script identity must be captured before mutable target inputs are consumed'
Assert-True ($buildRootInitOffset -ge 0 -and $smokeRootInitOffset -gt $buildRootInitOffset -and
        $runsRootInitOffset -gt $smokeRootInitOffset) `
    'repoRoot/build/platform-smoke/runs must be initialized one direct-parent level at a time'
Assert-True ($preBuildOffset -ge 0 -and $preBuildOffset -lt $firstBuildOffset -and
        $postBuildOffset -gt $firstBuildOffset) `
    'immutable input closure must be snapshotted before build and compared after build'
Assert-True ($preStartRunLocalOffset -ge 0 -and $preStartRunLocalOffset -lt $firstStartOffset) `
    'run-local server/plugin/prepared closure must be verified before process start'
Assert-True ($policyTupleOffset -gt $firstStartOffset -and
        $velocityRestartOffset -gt $policyTupleOffset) `
    'Velocity policy tuple must be rewritten and read back after first startup but before restart'
Assert-True ($afterRunOffset -gt $firstStartOffset -and $finalSourceOffset -gt $afterRunOffset) `
    'run-local and source closure must be recomputed after process execution'

$assetVerifier = Get-TargetFunctionAst 'Assert-FabricAssetCache'
$preparedVerifier = Get-TargetFunctionAst 'Get-PreparedPaperBinding'
$sourceManifestVerifier = Get-TargetFunctionAst 'Get-SourceManifestBinding'
$immutableSnapshot = Get-TargetFunctionAst 'Get-ImmutableInputSnapshot'
$runLocalBinding = Get-TargetFunctionAst 'Get-RunLocalRuntimeBinding'
foreach ($functionAst in @($assetVerifier, $preparedVerifier, $sourceManifestVerifier,
        $immutableSnapshot, $runLocalBinding)) {
    Assert-True ($null -ne $functionAst) 'required immutable-input closure function is missing'
}
foreach ($contract in @(
        'Get-Sha1 $versionInfoPath',
        'Get-Sha256 $versionInfoPath',
        "`$indexFileName = '{0}-{1}.json' -f [string]`$fabricDescriptor.minecraft_version, [string]`$assetIndex.id",
        "Join-Path `$loomCache (Join-Path 'assets\indexes' `$indexFileName)",
        'Get-Sha1 $indexPath',
        'Get-Sha256 $indexPath',
        'Get-ManifestSha256 $manifestEntries.ToArray()')) {
    Assert-True ($assetVerifier.Extent.Text.IndexOf($contract, [StringComparison]::Ordinal) -ge 0) `
        "Fabric asset closure is missing: $contract"
}
foreach ($contract in @(
        "'MCACE_SERVER_VERSION_MATRIX_PREPARED_V1'",
        "(@(`$manifest.roots) -join ',') -cne 'cache,libraries,versions'",
        '@($manifest.trees).Count -ne 6',
        "`$tree.project -notin @('paper', 'folia')",
        "`$seenTrees.Count -ne `$sourceAssets.Count",
        'Get-PreparedTreeBinding $preparedPaperRoot',
        'PLATFORM_SMOKE_PREPARED_TARGET_TREE_CONTENT_MISMATCH')) {
    Assert-True ($preparedVerifier.Extent.Text.IndexOf($contract, [StringComparison]::Ordinal) -ge 0) `
        "prepared-manifest V1 closure is missing: $contract"
}
foreach ($contract in @(
        "@('build.gradle.kts', 'settings.gradle.kts', 'gradle.properties'",
        "Join-Path `$repoRoot 'gradle'",
        "-Filter 'mcace-*'",
        "foreach (`$name in @('build.gradle.kts', 'gradle.lockfile'))",
        "Join-Path `$module.FullName 'src'",
        "Join-Path `$repoRoot 'fabric-modern'",
        "'gradle\verification-metadata.xml'",
        "'client-26.1.2\gradle.lockfile'",
        "'client-26.2\gradle.lockfile'",
        "Join-Path `$modernRoot 'src'")) {
    Assert-True ($sourceManifestVerifier.Extent.Text.IndexOf(
            $contract, [StringComparison]::Ordinal) -ge 0) `
        "source input manifest closure is missing: $contract"
}
foreach ($contract in @(
        'Get-SourceManifestBinding',
        'Get-PreparedPaperBinding',
        'Assert-FabricAssetCache ([bool]$WithFabricClient -or [bool]$ReportOnly)',
        'server_matrix_manifest_sha256',
        'paper_prepared_manifest_sha256',
        'paper_prepared_tree_sha256',
        'fabric_asset_object_manifest_sha256')) {
    Assert-True ($immutableSnapshot.Extent.Text.IndexOf($contract, [StringComparison]::Ordinal) -ge 0) `
        "immutable input snapshot is missing: $contract"
}
foreach ($contract in @(
        "Join-Path `$velocityRoot 'velocity.jar'",
        "Join-Path `$paperRoot 'paper.jar'",
        "Join-Path `$velocityRoot 'plugins\mcace.jar'",
        "Join-Path `$paperRoot 'plugins\mcace.jar'",
        'Get-PreparedTreeBinding $paperRoot')) {
    Assert-True ($runLocalBinding.Extent.Text.IndexOf($contract, [StringComparison]::Ordinal) -ge 0) `
        "run-local runtime closure is missing: $contract"
}

# Execute the ownership helpers in PS7 and Windows PowerShell 5.1.  The fixture proves
# lower-case 128-bit run leaves, fail-if-exists directory creation, retention boundaries,
# and rejection of both nested and runs-root junctions without touching their targets.
$pathHelperNames = @(
    'Assert-DirectLocalPath',
    'Test-SmokeRunLeaf',
    'Assert-SmokeRunLeaf',
    'Initialize-SafeOwnedDirectory',
    'New-ExclusiveOwnedDirectory',
    'Assert-OwnedTreeNoReparse',
    'Remove-UnretainedDiagnostics'
)
foreach ($name in $pathHelperNames) {
    $functionAst = Get-TargetFunctionAst $name
    Assert-True ($null -ne $functionAst) "path ownership helper is missing: $name"
    Invoke-Expression $functionAst.Extent.Text
}

# Exercise the exact Loom cache naming contract in both supported PowerShell runtimes.
# Each reviewed target gets a fully pinned version-info -> index -> object fixture using
# Loom's <minecraftVersion>-<assetIndex.id>.json filename.  A legacy pure-ID index is
# deliberately left in place after the canonical file is removed and must not be accepted.
foreach ($name in @('Get-Sha256', 'Get-Sha1', 'Get-BytesSha256', 'Get-ManifestSha256',
        'Assert-FabricAssetCache')) {
    $functionAst = Get-TargetFunctionAst $name
    Assert-True ($null -ne $functionAst) "Fabric asset fixture helper is missing: $name"
    Invoke-Expression $functionAst.Extent.Text
}
$assetFixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'mcace-platform-assets-' + [Guid]::NewGuid().ToString('N'))
$previousGradleUserHome = [Environment]::GetEnvironmentVariable('GRADLE_USER_HOME', 'Process')
try {
    $assetGradleRoot = Join-Path $assetFixtureRoot '.gradle'
    $loomFixtureRoot = Join-Path $assetGradleRoot 'caches\fabric-loom'
    $indexFixtureRoot = Join-Path $loomFixtureRoot 'assets\indexes'
    $null = New-Item -ItemType Directory -Path $indexFixtureRoot -Force -ErrorAction Stop
    $env:GRADLE_USER_HOME = $assetGradleRoot
    $fixtureUtf8 = [System.Text.UTF8Encoding]::new($false)

    foreach ($targetName in @($fabricTargets.Keys)) {
        $reviewedDescriptor = $fabricTargets[$targetName]
        $assetIndexId = [string]$reviewedDescriptor.asset_index
        $objectStagingPath = Join-Path $assetFixtureRoot (
            'object-{0}.bin' -f $targetName.Replace('.', '_'))
        $objectBytes = $fixtureUtf8.GetBytes("mcace-loom-asset-fixture-$targetName")
        [System.IO.File]::WriteAllBytes($objectStagingPath, $objectBytes)
        $objectSha1 = Get-Sha1 $objectStagingPath
        $objectPath = Join-Path $loomFixtureRoot (
            'assets\objects\{0}\{1}' -f $objectSha1.Substring(0, 2), $objectSha1)
        $null = New-Item -ItemType Directory -Path (Split-Path -Path $objectPath -Parent) `
            -Force -ErrorAction Stop
        Move-Item -LiteralPath $objectStagingPath -Destination $objectPath -ErrorAction Stop

        $indexPath = Join-Path $indexFixtureRoot ("$targetName-$assetIndexId.json")
        $indexFixture = [ordered]@{
            objects = [ordered]@{
                fixture = [ordered]@{
                    hash = $objectSha1
                    size = [long]$objectBytes.Length
                }
            }
        }
        [System.IO.File]::WriteAllText(
            $indexPath, ($indexFixture | ConvertTo-Json -Depth 5), $fixtureUtf8)
        $indexSha1 = Get-Sha1 $indexPath
        $indexSha256 = Get-Sha256 $indexPath
        $indexSize = [long](Get-Item -LiteralPath $indexPath).Length

        $versionInfoPath = Join-Path $loomFixtureRoot (
            '{0}\mojang_minecraft_info.json' -f $targetName)
        $null = New-Item -ItemType Directory -Path (Split-Path -Path $versionInfoPath -Parent) `
            -Force -ErrorAction Stop
        $versionInfoFixture = [ordered]@{
            id = $targetName
            javaVersion = [ordered]@{ majorVersion = [int]$reviewedDescriptor.java_major }
            assetIndex = [ordered]@{
                id = $assetIndexId
                sha1 = $indexSha1
                size = $indexSize
                url = "https://piston-meta.mojang.com/v1/packages/$indexSha1/$assetIndexId.json"
            }
        }
        [System.IO.File]::WriteAllText(
            $versionInfoPath, ($versionInfoFixture | ConvertTo-Json -Depth 5), $fixtureUtf8)

        $FabricTarget = $targetName
        $fabricDescriptor = [ordered]@{
            minecraft_version = $targetName
            java_major = [int]$reviewedDescriptor.java_major
            asset_index = $assetIndexId
            version_info_sha1 = Get-Sha1 $versionInfoPath
            version_info_sha256 = Get-Sha256 $versionInfoPath
            asset_index_sha1 = $indexSha1
            asset_index_size = $indexSize
        }
        $assetBinding = Assert-FabricAssetCache $true
        Assert-True ([bool]$assetBinding.fabric_asset_cache_verified) `
            "canonical Loom asset fixture was not verified: $targetName"
        Assert-True ([string]$assetBinding.fabric_version_info_sha1 -ceq
            [string]$fabricDescriptor.version_info_sha1) `
            "version-info SHA-1 closure drifted: $targetName"
        Assert-True ([string]$assetBinding.fabric_version_info_sha256 -ceq
            [string]$fabricDescriptor.version_info_sha256) `
            "version-info SHA-256 closure drifted: $targetName"
        Assert-True ([string]$assetBinding.fabric_asset_index_id -ceq $assetIndexId -and
                [string]$assetBinding.fabric_asset_index_sha1 -ceq $indexSha1 -and
                [string]$assetBinding.fabric_asset_index_sha256 -ceq $indexSha256 -and
                [long]$assetBinding.fabric_asset_index_size -eq $indexSize) `
            "asset-index identity closure drifted: $targetName"
        Assert-True ([int]$assetBinding.fabric_asset_object_count -eq 1 -and
                [long]$assetBinding.fabric_asset_object_total_size -eq [long]$objectBytes.Length -and
                [string]$assetBinding.fabric_asset_object_manifest_sha256 -ceq
                (Get-ManifestSha256 @("$objectSha1|$($objectBytes.Length)"))) `
            "asset-object closure drifted: $targetName"

        $legacyIndexPath = Join-Path $indexFixtureRoot ("$assetIndexId.json")
        [System.IO.File]::Copy($indexPath, $legacyIndexPath, $true)
        Remove-Item -LiteralPath $indexPath -Force
        $legacyIndexRejected = $false
        try { $null = Assert-FabricAssetCache $true }
        catch {
            $legacyIndexRejected = $_.Exception.Message -ceq
                "PLATFORM_SMOKE_FABRIC_ASSET_INDEX_CACHE_REQUIRED: $targetName"
        }
        Assert-True $legacyIndexRejected `
            "legacy pure-ID Loom asset index was accepted: $targetName/$assetIndexId.json"
    }
} finally {
    [Environment]::SetEnvironmentVariable(
        'GRADLE_USER_HOME', $previousGradleUserHome, 'Process')
    if (Test-Path -LiteralPath $assetFixtureRoot) {
        Remove-Item -LiteralPath $assetFixtureRoot -Recurse -Force
    }
}

$policyTupleSetter = Get-TargetFunctionAst 'Set-ExactVelocityPolicyTuple'
Assert-True ($null -ne $policyTupleSetter) 'exact Velocity policy-tuple setter is missing'
Invoke-Expression $policyTupleSetter.Extent.Text
$exclusiveCreator = Get-TargetFunctionAst 'New-ExclusiveOwnedDirectory'
$exclusiveCreateCalls = @($exclusiveCreator.Body.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq 'New-Item'
}, $true))
Assert-True ($exclusiveCreateCalls.Count -eq 1 -and
        $exclusiveCreateCalls[0].Extent.Text -ceq
        'New-Item -ItemType Directory -Path $full -ErrorAction Stop') `
    'exclusive run-directory creation must retain fail-if-exists New-Item semantics without Force'

$generatorAst = Get-TargetFunctionAst 'New-SmokeRunToken'
Assert-True ($null -ne $generatorAst) 'CSPRNG run-token generator is missing'
Invoke-Expression $generatorAst.Extent.Text
$generatedTokens = @(1..16 | ForEach-Object { New-SmokeRunToken })
Assert-True (@($generatedTokens | Sort-Object -Unique).Count -eq 16) `
    'CSPRNG run-token fixture produced a duplicate token'
Assert-True (@($generatedTokens | Where-Object { $_ -cnotmatch '^[0-9a-f]{32}$' }).Count -eq 0) `
    'CSPRNG run-token fixture produced a non-canonical token'

$fixtureBase = Join-Path ([System.IO.Path]::GetTempPath()) (
    'mcace-platform-load-static-' + [Guid]::NewGuid().ToString('N'))
$outsideBase = Join-Path ([System.IO.Path]::GetTempPath()) (
    'mcace-platform-load-outside-' + [Guid]::NewGuid().ToString('N'))
$nestedJunction = $null
$runsJunction = $null
try {
    $null = New-Item -ItemType Directory -Path $fixtureBase -ErrorAction Stop
    $null = New-Item -ItemType Directory -Path $outsideBase -ErrorAction Stop
    $fixtureBase = Assert-DirectLocalPath $fixtureBase -Directory
    $outsideBase = Assert-DirectLocalPath $outsideBase -Directory
    $buildFixture = Initialize-SafeOwnedDirectory (Join-Path $fixtureBase 'build') $fixtureBase
    $smokeFixture = Initialize-SafeOwnedDirectory (Join-Path $buildFixture 'platform-smoke') $buildFixture
    $runsRoot = Initialize-SafeOwnedDirectory (Join-Path $smokeFixture 'runs') $smokeFixture
    Assert-True ([System.IO.Path]::GetDirectoryName($buildFixture).Equals(
            $fixtureBase, [StringComparison]::OrdinalIgnoreCase)) `
        'dynamic fixture did not create build as a direct repoRoot child'
    Assert-True ([System.IO.Path]::GetDirectoryName($smokeFixture).Equals(
            $buildFixture, [StringComparison]::OrdinalIgnoreCase)) `
        'dynamic fixture did not create platform-smoke as a direct build child'
    Assert-True ([System.IO.Path]::GetDirectoryName($runsRoot).Equals(
            $smokeFixture, [StringComparison]::OrdinalIgnoreCase)) `
        'dynamic fixture did not create runs as a direct platform-smoke child'

    $policyBuildId = 'platform-smoke-20260814T010203004Z'
    $policyFixture = Join-Path $fixtureBase 'mcace.properties'
    [System.IO.File]::WriteAllText(
        $policyFixture,
        "# fixture`r`n policy.minecraft-versions : 1.21.11`r`npolicy.client-build-ids=old-build`r`nhandshake.timeout.seconds=9`r`n",
        [System.Text.UTF8Encoding]::new($false))
    $policyTuple = Set-ExactVelocityPolicyTuple $policyFixture '26.1.2' $policyBuildId
    Assert-True ([string]$policyTuple.velocity_policy_minecraft_versions -ceq '26.1.2') `
        'Velocity policy fixture returned the wrong Minecraft version'
    Assert-True ([string]$policyTuple.velocity_policy_client_build_ids -ceq $policyBuildId) `
        'Velocity policy fixture returned the wrong client build ID'
    $policyReadback = [System.IO.File]::ReadAllText($policyFixture)
    $policyLines = @($policyReadback -split '\r?\n')
    Assert-True (@($policyLines | Where-Object { $_ -ceq 'policy.minecraft-versions=26.1.2' }).Count -eq 1) `
        'Velocity policy fixture did not write exactly one canonical Minecraft-version line'
    Assert-True (@($policyLines | Where-Object { $_ -ceq "policy.client-build-ids=$policyBuildId" }).Count -eq 1) `
        'Velocity policy fixture did not write exactly one canonical client-build line'
    Assert-True (@($policyLines | Where-Object { $_ -ceq 'handshake.timeout.seconds=9' }).Count -eq 1) `
        'Velocity policy fixture changed an unrelated property'

    foreach ($invalidPolicyFixture in @(
            [ordered]@{
                name = 'duplicate-minecraft-version'
                content = "policy.minecraft-versions=1.21.11`npolicy.minecraft-versions 26.2`npolicy.client-build-ids=old`n"
                error = 'PLATFORM_SMOKE_VELOCITY_POLICY_KEY_COUNT_INVALID: policy.minecraft-versions'
            },
            [ordered]@{
                name = 'duplicate-client-build-id'
                content = "policy.minecraft-versions=1.21.11`npolicy.client-build-ids=old`npolicy.client-build-ids:other`n"
                error = 'PLATFORM_SMOKE_VELOCITY_POLICY_KEY_COUNT_INVALID: policy.client-build-ids'
            },
            [ordered]@{
                name = 'missing-minecraft-version'
                content = "policy.client-build-ids=old`nhandshake.timeout.seconds=9`n"
                error = 'PLATFORM_SMOKE_VELOCITY_POLICY_KEY_COUNT_INVALID: policy.minecraft-versions'
            },
            [ordered]@{
                name = 'missing-client-build-id'
                content = "policy.minecraft-versions=1.21.11`nhandshake.timeout.seconds=9`n"
                error = 'PLATFORM_SMOKE_VELOCITY_POLICY_KEY_COUNT_INVALID: policy.client-build-ids'
            })) {
        $invalidPolicyPath = Join-Path $fixtureBase ($invalidPolicyFixture.name + '.properties')
        [System.IO.File]::WriteAllText(
            $invalidPolicyPath, [string]$invalidPolicyFixture.content,
            [System.Text.UTF8Encoding]::new($false))
        $invalidPolicyBefore = [System.IO.File]::ReadAllText($invalidPolicyPath)
        $invalidPolicyRejected = $false
        try {
            $null = Set-ExactVelocityPolicyTuple $invalidPolicyPath '26.2' $policyBuildId
        } catch {
            $invalidPolicyRejected = $_.Exception.Message -ceq [string]$invalidPolicyFixture.error
        }
        Assert-True $invalidPolicyRejected `
            "Velocity policy fixture was not rejected exactly: $($invalidPolicyFixture.name)"
        Assert-True ([System.IO.File]::ReadAllText($invalidPolicyPath) -ceq $invalidPolicyBefore) `
            "Velocity policy rejection partially rewrote the config: $($invalidPolicyFixture.name)"
    }

    $validLeaf = '20260814T010203004Z-26_1_2-0123456789abcdef0123456789abcdef'
    Assert-True (Test-SmokeRunLeaf $validLeaf) 'canonical CSPRNG run leaf was rejected'
    foreach ($invalidLeaf in @(
            '20260814T010203004Z',
            '20260814T010203004Z-26_1_2',
            '20260814T010203004Z-26_1_2-0123456789ABCDEF0123456789ABCDEF',
            '20260814T010203004Z-1_21_10-0123456789abcdef0123456789abcdef')) {
        Assert-True (-not (Test-SmokeRunLeaf $invalidLeaf)) `
            "invalid run leaf was accepted: $invalidLeaf"
    }

    $runFixture = New-ExclusiveOwnedDirectory (Join-Path $runsRoot $validLeaf) $runsRoot
    $duplicateRejected = $false
    try { $null = New-ExclusiveOwnedDirectory $runFixture $runsRoot }
    catch { $duplicateRejected = $_.Exception.Message -eq 'PLATFORM_SMOKE_EXCLUSIVE_DIRECTORY_ALREADY_EXISTS' }
    Assert-True $duplicateRejected 'exclusive run-directory creation accepted an existing leaf'

    $reportFixture = Join-Path $runFixture 'report.json'
    $bindingFixture = Join-Path $runFixture 'binding.json'
    $diagnosticFixture = Join-Path $runFixture 'diagnostics'
    [System.IO.File]::WriteAllText($reportFixture, '{}')
    [System.IO.File]::WriteAllText($bindingFixture, '{}')
    $null = New-Item -ItemType Directory -Path $diagnosticFixture -ErrorAction Stop
    [System.IO.File]::WriteAllText((Join-Path $diagnosticFixture 'private.log'), 'private')
    Remove-UnretainedDiagnostics $runFixture $reportFixture $bindingFixture
    Assert-True (Test-Path -LiteralPath $reportFixture -PathType Leaf) `
        'safe diagnostics cleanup removed report.json'
    Assert-True (Test-Path -LiteralPath $bindingFixture -PathType Leaf) `
        'safe diagnostics cleanup removed binding.json'
    Assert-True (-not (Test-Path -LiteralPath $diagnosticFixture)) `
        'safe diagnostics cleanup retained an unrequested diagnostic tree'

    $outsideNested = Initialize-SafeOwnedDirectory (Join-Path $outsideBase 'nested-target') $outsideBase
    $outsideSentinel = Join-Path $outsideNested 'sentinel.txt'
    [System.IO.File]::WriteAllText($outsideSentinel, 'outside-owned')
    $nestedJunction = Join-Path $runFixture 'linked-diagnostics'
    $null = New-Item -ItemType Junction -Path $nestedJunction -Target $outsideNested -ErrorAction Stop
    $nestedRejected = $false
    try { Remove-UnretainedDiagnostics $runFixture $reportFixture $bindingFixture }
    catch { $nestedRejected = $_.Exception.Message -like 'PLATFORM_SMOKE_REPARSE_TREE_ENTRY_REJECTED*' }
    Assert-True $nestedRejected 'safe diagnostics cleanup accepted a nested junction'
    Assert-True (([System.IO.File]::ReadAllText($outsideSentinel)) -ceq 'outside-owned') `
        'nested-junction rejection changed the outside sentinel'
    [System.IO.Directory]::Delete($nestedJunction)
    $nestedJunction = $null

    $outsideRuns = Initialize-SafeOwnedDirectory (Join-Path $outsideBase 'runs-target') $outsideBase
    $outsideRunLeaf = '20260814T010203005Z-26_2-fedcba9876543210fedcba9876543210'
    $outsideRun = New-ExclusiveOwnedDirectory (Join-Path $outsideRuns $outsideRunLeaf) $outsideRuns
    $outsideReport = Join-Path $outsideRun 'report.json'
    $outsideDiagnostic = Join-Path $outsideRun 'private.log'
    [System.IO.File]::WriteAllText($outsideReport, '{}')
    [System.IO.File]::WriteAllText($outsideDiagnostic, 'outside-private')
    $runsJunction = Join-Path $smokeFixture 'linked-runs'
    $null = New-Item -ItemType Junction -Path $runsJunction -Target $outsideRuns -ErrorAction Stop
    $runsRoot = $runsJunction
    $rootRejected = $false
    try {
        Remove-UnretainedDiagnostics (Join-Path $runsJunction $outsideRunLeaf) `
            (Join-Path (Join-Path $runsJunction $outsideRunLeaf) 'report.json')
    } catch {
        $rootRejected = $_.Exception.Message -eq 'PLATFORM_SMOKE_REPARSE_PATH_REJECTED'
    }
    Assert-True $rootRejected 'safe diagnostics cleanup accepted a junction as runsRoot'
    Assert-True (([System.IO.File]::ReadAllText($outsideDiagnostic)) -ceq 'outside-private') `
        'runs-root junction rejection removed outside diagnostics'
    [System.IO.Directory]::Delete($runsJunction)
    $runsJunction = $null
} finally {
    foreach ($junction in @($nestedJunction, $runsJunction)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$junction) -and
                (Test-Path -LiteralPath $junction)) {
            [System.IO.Directory]::Delete($junction)
        }
    }
    if (Test-Path -LiteralPath $fixtureBase) {
        Remove-Item -LiteralPath $fixtureBase -Recurse -Force
    }
    if (Test-Path -LiteralPath $outsideBase) {
        Remove-Item -LiteralPath $outsideBase -Recurse -Force
    }
}

$fabricClientTargets = @(
    [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot `
        '..\mcace-client-fabric\src\main\java\com\ellan\mcace\fabric\MCAceFabricClient.java')),
    [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot `
        '..\fabric-modern\src\main\java\com\ellan\mcace\fabric\MCAceFabricClient.java'))
)
$contentFreeMarker = 'LOGGER.info("MCAce explicit-file manifest prepared entries={}", explicitEntries);'
foreach ($fabricClientTarget in $fabricClientTargets) {
    $fabricClientSource = [System.IO.File]::ReadAllText($fabricClientTarget)
    Assert-True ($fabricClientSource.IndexOf($contentFreeMarker, [StringComparison]::Ordinal) -ge 0) `
        "Fabric client content-free explicit-file entry marker is missing or changed: $fabricClientTarget"
    foreach ($requiredArtifactOriginContract in @(
            'mcace.platform-smoke.expected-artifact-sha256',
            'FabricClientBuildMetadata.verifiedCodeSourceSha256(',
            'buildMetadata.artifactLoadedMarker(actualArtifactSha256)')) {
        Assert-True ($fabricClientSource.IndexOf(
                $requiredArtifactOriginContract, [StringComparison]::Ordinal) -ge 0) `
            "Fabric client loaded-CodeSource contract is missing: $requiredArtifactOriginContract"
    }
}

$fabricBuildTarget = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot `
    '..\mcace-client-fabric\build.gradle.kts'))
$fabricBuildSource = [System.IO.File]::ReadAllText($fabricBuildTarget)
foreach ($requiredArtifactModeClosure in @(
        'com/ellan/mcace/fabric/MCAceFabricClient.class',
        'jar.getJarEntry("fabric.mod.json")',
        'metadata["id"] == "mcace"',
        'it != runtimeArtifact && containsConflictingMcaceFabricOrigin(it)',
        'check(conflictingOrigins.isEmpty())',
        'sha256(runtimeArtifact) == expectedArtifactSha256',
        'systemProperty("mcace.platform-smoke.expected-artifact-sha256", expectedArtifactSha256)',
        'systemProperty("mcace.smoke.run-token", runToken)')) {
    Assert-True ($fabricBuildSource.IndexOf(
            $requiredArtifactModeClosure, [StringComparison]::Ordinal) -ge 0) `
        "Fabric artifact-mode closure is missing: $requiredArtifactModeClosure"
}

$modernFabricBuildTarget = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot `
    '..\fabric-modern\build.gradle.kts'))
$modernFabricBuildSource = [System.IO.File]::ReadAllText($modernFabricBuildTarget)
foreach ($requiredModernArtifactModeClosure in @(
        'loomExtension.mods.configureEach',
        'modFiles.setFrom(emptyList<Any>())',
        'loomExtension.mods.maybeCreate("mcace")',
        'modFiles.setFrom(deployableJar)',
        'modernMainOutputRoots.get() + stagedRootJarPaths.get()',
        'check(nonEmptyMods == listOf("mcace" to setOf(artifact)))',
        'check(leakedOrigins.isEmpty())',
        'it != artifact && containsConflictingMcaceFabricOrigin(it)',
        'check(conflictingOrigins.isEmpty())',
        'sha256(artifact) == expectedArtifactSha256',
        '"mcace.platform-smoke.expected-artifact-sha256",',
        'systemProperty("mcace.smoke.run-token", runToken)',
        'runDirectory.set(file(smokeRunDirectory.get()))',
        'systemProperties.put("mcace.platform-smoke.server-address", smokeServerAddress.get())',
        'check(JavaVersion.current().majorVersion == "25")')) {
    Assert-True ($modernFabricBuildSource.IndexOf(
            $requiredModernArtifactModeClosure, [StringComparison]::Ordinal) -ge 0) `
        "Modern Fabric artifact-mode closure is missing: $requiredModernArtifactModeClosure"
}

Write-Output 'PLATFORM_LOAD_SMOKE_PRIVACY_STATIC_PASS'
