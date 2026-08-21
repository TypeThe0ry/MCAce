[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$target = Join-Path $PSScriptRoot 'fabric-federation-gui-handoff-smoke.ps1'
$platformTarget = Join-Path $PSScriptRoot 'platform-load-smoke.ps1'
$repoRoot = Split-Path -Parent $PSScriptRoot
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $target, [ref]$tokens, [ref]$errors)
if (@($errors).Count -ne 0) {
    throw "FABRIC_FEDERATION_GUI_STATIC_PARSE_FAILED: $($errors -join '; ')"
}
$platformTokens = $null
$platformErrors = $null
$platformAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $platformTarget, [ref]$platformTokens, [ref]$platformErrors)
if (@($platformErrors).Count -ne 0) {
    throw "FABRIC_FEDERATION_GUI_PLATFORM_STATIC_PARSE_FAILED: $($platformErrors -join '; ')"
}
$source = [System.IO.File]::ReadAllText($target)
$platformSource = [System.IO.File]::ReadAllText($platformTarget)

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "FABRIC_FEDERATION_GUI_STATIC_FAILED: $Message" }
}

function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $threw = $false
    try { & $Action }
    catch { $threw = $true }
    Assert-True $threw $Message
}

function Get-Parameter([string]$Name) {
    return @($ast.ParamBlock.Parameters | Where-Object {
        $_.Name.VariablePath.UserPath -ceq $Name
    }) | Select-Object -First 1
}

function Test-MandatoryParameter([string]$Name, [string]$Set) {
    $parameter = Get-Parameter $Name
    if ($null -eq $parameter) { return $false }
    foreach ($attribute in $parameter.Attributes) {
        if ($attribute.TypeName.FullName -cne 'Parameter') { continue }
        $mandatory = $false
        $parameterSet = ''
        foreach ($named in $attribute.NamedArguments) {
            if ($named.ArgumentName -ceq 'Mandatory') { $mandatory = $true }
            if ($named.ArgumentName -ceq 'ParameterSetName') {
                $parameterSet = $named.Argument.Extent.Text.Trim("'", '"')
            }
        }
        if ($mandatory -and $parameterSet -ceq $Set) { return $true }
    }
    return $false
}

function Get-ValidateSet([string]$Name) {
    $parameter = Get-Parameter $Name
    if ($null -eq $parameter) { return @() }
    $attribute = @($parameter.Attributes | Where-Object {
        $_.TypeName.FullName -ceq 'ValidateSet'
    }) | Select-Object -First 1
    if ($null -eq $attribute) { return @() }
    return @($attribute.PositionalArguments | ForEach-Object {
        if ($_ -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            [string]$_.Value
        } else {
            $_.Extent.Text.Trim("'", '"')
        }
    })
}

function Get-AssignmentAst(
        [System.Management.Automation.Language.Ast]$Root,
        [string]$VariableText) {
    $matches = @($Root.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq $VariableText
    }, $true))
    Assert-True ($matches.Count -eq 1) "$VariableText assignment must exist exactly once"
    return $matches[0]
}

function Get-FunctionText(
        [System.Management.Automation.Language.Ast]$Root,
        [string[]]$Names) {
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $Names) {
        $matches = @($Root.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $name
        }, $true))
        Assert-True ($matches.Count -eq 1) "function $name must exist exactly once"
        $parts.Add($matches[0].Extent.Text)
    }
    return $parts -join "`n`n"
}

function Get-TextSha256([string]$Text) {
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Copy-JsonObject([object]$Value) {
    $raw = $Value | ConvertTo-Json -Depth 12 -Compress
    $command = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
    if ($command.Parameters.ContainsKey('DateKind')) {
        return ConvertFrom-Json -InputObject $raw -DateKind String -ErrorAction Stop
    }
    return ConvertFrom-Json -InputObject $raw -ErrorAction Stop
}

function Assert-ReportMutationRejected(
        [System.Management.Automation.PSModuleInfo]$Validator,
        [object]$Report,
        [System.Collections.IDictionary]$Current,
        [string]$Property,
        [object]$Value,
        [string]$Message) {
    $mutated = Copy-JsonObject $Report
    $mutated.$Property = $Value
    $raw = $mutated | ConvertTo-Json -Depth 12 -Compress
    Assert-Throws {
        & $Validator {
            param($Json, $Binding)
            Assert-PassingReportRaw $Json $Binding 'VELOCITY' 'BUNGEE'
        } $raw $Current
    } $Message
}

$parameters = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
$expectedParameters = @(
    'Execute', 'ReportOnly', 'FabricTarget', 'SourceProxy', 'TargetProxy',
    'SourceExportHumanAttested', 'TargetImportHumanAttested',
    'ExpectedFabricArtifactSha256', 'ExpectedVelocityPluginSha256',
    'ExpectedBungeePluginSha256', 'ExpectedPaperPluginSha256',
    'ExpectedVelocityServerSha256', 'ExpectedBungeeServerSha256',
    'ExpectedPaperServerSha256', 'ExpectedPaperPreparedManifestSha256',
    'ExpectedPaperPreparedTreeSha256', 'ExpectedFabricVersionInfoSha256',
    'ExpectedFabricAssetIndexSha256', 'ExpectedFabricAssetObjectManifestSha256',
    'FederationAssertionTtlSeconds', 'HumanTransitionTimeoutSeconds',
    'MaximumReportAgeMinutes'
)
Assert-True ((($parameters | Sort-Object) -join "`n") -ceq
    (($expectedParameters | Sort-Object) -join "`n")) 'parameter surface is not exact'
Assert-True ($source -match "DefaultParameterSetName\s*=\s*'Disabled'") `
    'default parameter set is not disabled'
Assert-True (Test-MandatoryParameter 'Execute' 'Execute') 'Execute is not explicit and mandatory'
Assert-True (Test-MandatoryParameter 'ReportOnly' 'Report') 'ReportOnly is not explicit and mandatory'
foreach ($name in @('FabricTarget', 'SourceProxy', 'TargetProxy')) {
    Assert-True (Test-MandatoryParameter $name 'Execute') "$name is not mandatory for Execute"
    Assert-True (Test-MandatoryParameter $name 'Report') "$name is not mandatory for ReportOnly"
}
foreach ($name in @('SourceExportHumanAttested', 'TargetImportHumanAttested')) {
    Assert-True (Test-MandatoryParameter $name 'Execute') "$name is not a mandatory human Execute attestation"
    Assert-True (-not (Test-MandatoryParameter $name 'Report')) "$name leaks into ReportOnly"
}
$reportHashParameters = @(
    'ExpectedFabricArtifactSha256', 'ExpectedVelocityPluginSha256',
    'ExpectedBungeePluginSha256', 'ExpectedPaperPluginSha256',
    'ExpectedVelocityServerSha256', 'ExpectedBungeeServerSha256',
    'ExpectedPaperServerSha256', 'ExpectedPaperPreparedManifestSha256',
    'ExpectedPaperPreparedTreeSha256', 'ExpectedFabricVersionInfoSha256',
    'ExpectedFabricAssetIndexSha256', 'ExpectedFabricAssetObjectManifestSha256'
)
foreach ($name in $reportHashParameters) {
    Assert-True (Test-MandatoryParameter $name 'Report') "$name is not mandatory for ReportOnly"
    Assert-True (-not (Test-MandatoryParameter $name 'Execute')) "$name is incorrectly caller-supplied to Execute"
}
Assert-True (((Get-ValidateSet 'FabricTarget') -join ',') -ceq '1.21.11,26.1.2,26.2') `
    'FabricTarget is not the exact three-target matrix'
foreach ($name in @('SourceProxy', 'TargetProxy')) {
    Assert-True (((Get-ValidateSet $name) -join ',') -ceq 'VELOCITY,BUNGEE') `
        "$name proxy matrix is not exact"
    Assert-True ($source.Contains("`$$name = `$$name.ToUpperInvariant()")) `
        "$name is not normalized to the canonical target-bound leaf value"
}
foreach ($forbidden in @('ReportPath', 'BindingPath', 'CommitPath', 'EvidenceRoot',
        'RunRoot', 'FabricArtifactJar', 'PreparedPaperRoot', 'JavaPath', 'GradlePath')) {
    Assert-True ($forbidden -notin $parameters) "caller-controlled path parameter exposed: $forbidden"
}

$reportOnlyBranches = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.IfStatementAst] -and
        $node.Clauses.Count -gt 0 -and
        $node.Clauses[0].Item1.Extent.Text.Trim() -ceq '$ReportOnly'
}, $true))
Assert-True ($reportOnlyBranches.Count -eq 1) 'ReportOnly branch is not unique'
$reportOnly = $reportOnlyBranches[0]
$reportOnlyText = $reportOnly.Extent.Text
foreach ($required in @('Get-CurrentBinding', 'Assert-ReportOnlyExpectedBinding',
        'Get-LatestCompleteEvidenceReport', 'Assert-EvidenceTriplet')) {
    Assert-True ($reportOnlyText.Contains($required)) "ReportOnly does not validate $required"
}
Assert-True ($reportOnlyText -match '(?m)^\s*exit\s+0\s*$') 'ReportOnly does not exit before Execute'
$reportCommands = @($reportOnly.FindAll({
    param($node) $node -is [System.Management.Automation.Language.CommandAst]
}, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
foreach ($forbidden in @('Invoke-PinnedOfflineGradle', 'Start-FabricClient',
        'Start-FederationJavaService', 'Start-ProxyRuntime', 'Start-PaperRuntime',
        'Write-NewUtf8File', 'Write-EvidenceTriplet', 'New-ExclusiveOwnedDirectory',
        'Initialize-SafeOwnedDirectory', 'Remove-Item', 'Copy-Item', 'Move-Item')) {
    Assert-True ($forbidden -notin $reportCommands) "ReportOnly can mutate or execute: $forbidden"
}
foreach ($forbiddenText in @('WriteAllText', 'WriteAllBytes', 'CreateDirectory',
        'FileMode]::Create', 'FileMode]::CreateNew', 'Process]::new')) {
    Assert-True (-not $reportOnlyText.Contains($forbiddenText)) `
        "ReportOnly contains a mutation/process API: $forbiddenText"
}

$platformFunctionAssignment = Get-AssignmentAst $ast '$platformFunctionNames'
$platformFunctionNames = Invoke-Expression $platformFunctionAssignment.Right.Extent.Text
$requiredPlatformFunctions = @(
    'Resolve-ServerMatrixAssets', 'Assert-FabricAssetCache', 'Get-PreparedPaperBinding',
    'Resolve-RootJava21', 'Resolve-TargetJava', 'Resolve-OfflineGradle961',
    'Invoke-PinnedOfflineGradle', 'Get-FabricArtifactIdentity',
    'Assert-FabricArtifactMarker', 'Start-FabricClient', 'Get-RunTokenJavaProcesses',
    'Stop-RunTokenJavaProcesses', 'Stop-JavaService', 'Get-SourceManifestBinding',
    'Get-ManifestSha256', 'Get-PreparedTreeBinding', 'Get-BytesSha256'
)
foreach ($name in $requiredPlatformFunctions) {
    Assert-True ($name -cin $platformFunctionNames) "platform authority function not reused: $name"
}
Assert-True ($source.Contains('$platformAst = [System.Management.Automation.Language.Parser]::ParseFile')) `
    'platform wrapper is not parsed as the target/cache authority'
Assert-True ($source.Contains("`$fabricTargets = Invoke-Expression `$targetAssignments[0].Right.Extent.Text")) `
    'platform target descriptor is not reused exactly'
Assert-True ($source.Contains("((@(`$fabricTargets.Keys) -join ',') -cne '1.21.11,26.1.2,26.2')")) `
    'runtime target matrix is not exact'
foreach ($token in @('Assert-FabricAssetCache $true', 'Get-PreparedPaperBinding',
        '-PmcaceSmokeArtifactMode=true', '-PmcaceClientBuildId=',
        '-PmcaceSmokeExpectedArtifactSha256=', 'FABRIC_FEDERATION_GUI_ROOT_JDK21_BUILD_FAILED',
        'FABRIC_FEDERATION_GUI_MODERN_JDK25_BUILD_FAILED',
        'FABRIC_FEDERATION_GUI_FABRIC_ARTIFACT_VERIFY_FAILED')) {
    Assert-True ($source.Contains($token)) "platform-strength target/build token missing: $token"
}
foreach ($token in @('--offline', '--dependency-verification=strict', '--no-build-cache',
        '--no-configuration-cache', '--no-daemon', '--no-parallel', '--max-workers=1')) {
    Assert-True ($platformSource.Contains($token)) "reused platform build is not pinned/offline: $token"
}
foreach ($forbiddenCommand in @('Invoke-WebRequest', 'Invoke-RestMethod', 'Start-BitsTransfer',
        'curl.exe', 'wget.exe')) {
    Assert-True (-not $source.Contains($forbiddenCommand)) "runner contains network fetch: $forbiddenCommand"
}

$platformTargetsAssignment = Get-AssignmentAst $platformAst '$fabricTargets'
$fabricTargets = Invoke-Expression $platformTargetsAssignment.Right.Extent.Text
Assert-True (@($fabricTargets.Keys).Count -eq 3) 'platform target descriptor count changed'
Assert-True ((@($fabricTargets.Keys) -join ',') -ceq '1.21.11,26.1.2,26.2') `
    'platform target descriptor order/set changed'
foreach ($name in @($fabricTargets.Keys)) {
    $descriptor = $fabricTargets[$name]
    Assert-True ([string]$descriptor.minecraft_version -ceq $name) `
        "platform descriptor minecraft version mismatch: $name"
    Assert-True ([int]$descriptor.java_major -in @(21, 25)) `
        "platform descriptor Java major invalid: $name"
    Assert-True (-not [string]::IsNullOrWhiteSpace([string]$descriptor.runtime_mode)) `
        "platform descriptor runtime mode missing: $name"
}

foreach ($token in @(
        "project -ceq 'bungeecord'", "version -ceq '2085'", "build -ceq '2085'",
        'https://hub.spigotmc.org/jenkins/job/BungeeCord/2085/artifact/bootstrap/target/BungeeCord.jar',
        'e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce',
        '25599274L', "channel -cne 'REVIEWED'", "'1.21.11,26.1.2,26.2'")) {
    Assert-True ($source.Contains($token)) "reviewed Bungee 2085 contract missing: $token"
}

foreach ($schema in @('MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V2',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V2',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V2')) {
    Assert-True ($source.Contains($schema)) "V2 evidence schema missing: $schema"
}
foreach ($old in @('MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V1',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V1',
        'MCACE_FEDERATION_PROXY_MATRIX_EXECUTED', 'runtime-federation-matrix',
        'federation-target-restart-residual',
        'FABRIC_FEDERATION_GUI_TARGET_IMPORT_CONSENT_NOT_IMPLEMENTED_NO_PASS_MINTED')) {
    Assert-True (-not $source.Contains($old)) "old/raw-peer/fail-stop producer accepted: $old"
}
foreach ($token in @('Assert-PassingReportRaw', 'Assert-BindingRaw', 'Assert-CommitRaw',
        'Assert-EvidenceTriplet', 'Write-EvidenceTriplet', 'commit.json',
        'raw_peer_evidence_used', '[bool]$report.raw_peer_evidence_used',
        'FABRIC_FEDERATION_GUI_TARGET_BOUND_V2_EVIDENCE_TRIPLET_REQUIRED')) {
    Assert-True ($source.Contains($token)) "triplet/raw-peer rejection contract missing: $token"
}

$markers = @(
    'MCAce federation source export consent requested',
    'MCAce federation source export consent screen rendered',
    'MCAce federation source export consent allowed once',
    'MCAce federation target import consent requested',
    'MCAce federation target import consent screen rendered',
    'MCAce federation target import consent allowed once'
)
foreach ($marker in $markers) {
    Assert-True ([regex]::Matches($source, [regex]::Escape($marker)).Count -eq 1) `
        "human GUI marker must be declared exactly once: $marker"
}
$fileHelperModule = New-Module -ScriptBlock ([scriptblock]::Create(
        (Get-FunctionText $ast @('Get-FileText', 'Get-FileLiteralCount', 'Get-FileRegexCount'))))
try {
    $observedMarkerCount = & $fileHelperModule {
        param($Path, $Marker) Get-FileLiteralCount $Path $Marker
    } $target $markers[0]
    Assert-True ($observedMarkerCount -eq 1) 'runtime file marker helper does not count exact literals'
    $observedRegexCount = & $fileHelperModule {
        param($Path) Get-FileRegexCount $Path 'MCAce federation presentation status=OBSERVED player='
    } $target
    Assert-True ($observedRegexCount -eq 1) 'runtime file regex helper does not use one authoritative file'
    $missingText = & $fileHelperModule {
        param($Path) Get-FileText $Path
    } (Join-Path $PSScriptRoot 'definitely-missing-federation-gui-static-fixture')
    Assert-True ([string]$missingText -ceq '') 'runtime file marker helper does not return empty for missing files'
} finally {
    Remove-Module $fileHelperModule -Force
}
foreach ($forbiddenApi in @('SendKeys', 'mouse_event', 'SetCursorPos', 'java.awt.Robot',
        'user32.dll', 'UIAutomation', 'WindowsInput', 'InputSimulator', 'ClickInput')) {
    Assert-True (-not $source.Contains($forbiddenApi)) "GUI automation surface present: $forbiddenApi"
}
foreach ($token in @(
        'FABRIC_FEDERATION_GUI_TWO_EXPLICIT_HUMAN_ATTESTATIONS_REQUIRED',
        'Assert-ExactHumanGuiMarkers $fabricLog',
        'MCAce session verified at trust level VERIFIED with risk score 0',
        'Accepted signed MCAce admission state', 'admission=VERIFIED, trust=VERIFIED, risk=0',
        'MCAce: federation issue status=CONSENT_ISSUED',
        'MCAce federation consent response status=GRANT_READY',
        'MCAce stored a one-time federation grant in memory only',
        '$playerName left the game', 'source_disconnected_before_target_auth',
        'MCAce federation presentation status=OBSERVED player=', 'target_subject_bound',
        'observations=1', 'observations=0', 'observation_expired',
        'target_observation_status_one_before_expiry',
        'target_observation_status_zero_after_expiry',
        'target_paper_admission_verified', 'local_trust_risk_admission_unchanged',
        'target_session_connected_through_expiry', 'Assert-NewPaperVerifiedSnapshot',
        'Assert-TargetSessionStillConnected', 'FABRIC_FEDERATION_GUI_PRE_EXPIRY_OBSERVATION_PROOF_LATE')) {
    Assert-True ($source.Contains($token)) "runtime federation assertion missing: $token"
}
Assert-True ([regex]::Matches(
        $source, '(?m)^\s+Assert-NewPaperVerifiedSnapshot \$targetPaperService ').Count -eq 4) `
    'local trust/risk/Paper admission is not checked at all four evidence boundaries'
Assert-True ([regex]::Matches(
        $source, '(?m)^\s+Assert-TargetSessionStillConnected \$fabricClient ').Count -ge 6) `
    'target session is not continuously guarded through expiry'
foreach ($token in @('$sourceSubjectId', '$targetSubjectId',
        '[StringComparer]::OrdinalIgnoreCase.Equals($sourceSubjectId, $targetSubjectId)',
        '$targetService.StdoutPath', '$targetPaperService.StdoutPath',
        '$preExpiryStatusCutoff', '$earliestAssertionExpiry', '$consentIssueObservedAt',
        '$latestAssertionExpiry')) {
    Assert-True ($source.Contains($token)) "correlated runtime evidence token missing: $token"
}

foreach ($token in @('Get-FabricArtifactIdentity', 'Assert-FabricArtifactMarker',
        'MCACE_FABRIC_ARTIFACT_LOADED version=', 'code_source_sha256=',
        'fabric_codesource_sha256_observed = [string]$currentBinding.fabric_artifact_sha256',
        'remaining_owned_process_count', 'cleanup_ports_free',
        'Stop-RunTokenJavaProcesses $runToken', 'Clear-OwnedRunForEvidence $runRoot',
        'Write-EvidenceTriplet $runRoot $report $currentBinding',
        'Remove-OwnedRunDirectory $runRoot')) {
    Assert-True ($source.Contains($token)) "artifact/cleanup/commit contract missing: $token"
}
$clearCall = $source.LastIndexOf('Clear-OwnedRunForEvidence $runRoot', [StringComparison]::Ordinal)
$writeCall = $source.LastIndexOf('Write-EvidenceTriplet $runRoot $report $currentBinding', [StringComparison]::Ordinal)
$passCall = $source.LastIndexOf('FABRIC_FEDERATION_GUI_HANDOFF_PASS|$runRoot', [StringComparison]::Ordinal)
Assert-True ($clearCall -ge 0 -and $clearCall -lt $writeCall -and $writeCall -lt $passCall) `
    'raw runtime content is not cleared before commit and PASS'

$rootClientPath = Join-Path (Split-Path -Parent $PSScriptRoot) `
    'mcace-client-fabric\src\main\java\com\ellan\mcace\fabric\MCAceFabricClient.java'
$modernClientPath = Join-Path (Split-Path -Parent $PSScriptRoot) `
    'fabric-modern\src\main\java\com\ellan\mcace\fabric\MCAceFabricClient.java'
$vaultPath = Join-Path (Split-Path -Parent $PSScriptRoot) `
    'mcace-client-common\src\main\java\com\ellan\mcace\client\federation\FederationTokenVault.java'
$federationRuntimePath = Join-Path (Split-Path -Parent $PSScriptRoot) `
    'mcace-core\src\main\java\com\ellan\mcace\core\federation\FederationRuntime.java'
$federationDocumentsPath = Join-Path (Split-Path -Parent $PSScriptRoot) `
    'mcace-protocol\src\main\java\com\ellan\mcace\protocol\federation\FederationDocuments.java'
foreach ($clientPath in @($rootClientPath, $modernClientPath)) {
    $client = [System.IO.File]::ReadAllText($clientPath)
    foreach ($marker in $markers) {
        Assert-True ([regex]::Matches($client, [regex]::Escape($marker)).Count -eq 1) `
            "product marker is not exact in $clientPath`: $marker"
    }
    foreach ($call in @('federationVault.onConnectionClosed()',
            'federationVault.cancelTargetClaims()', 'federationVault.newTargetHandshake(',
            'federationVault.preparePresentation(', 'federationVault.commit(prepared)',
            'federationVault.close()')) {
        Assert-True ($client.Contains($call)) "product lifecycle call missing in $clientPath`: $call"
    }
}
$vault = [System.IO.File]::ReadAllText($vaultPath)
foreach ($contract in @('public synchronized void onConnectionClosed()',
        'public synchronized void cancelTargetClaims()',
        'if (entry.boundTargetKeyVerified || entry.sourceConnectionClosed)',
        'entry.sourceConnectionClosed = true', 'if (entry.boundTargetKeyVerified)',
        'public synchronized void close()')) {
    Assert-True ($vault.Contains($contract)) "vault disconnect/claim lifecycle missing: $contract"
}
$federationRuntime = [System.IO.File]::ReadAllText($federationRuntimePath)
$federationDocuments = [System.IO.File]::ReadAllText($federationDocumentsPath)
foreach ($contract in @('FederationDocuments.issueConsentRequest(',
        'clock, current.assertionLifetime(), secureRandom',
        'Instant expiresAt = Instant.ofEpochMilli(verified.expiresAtEpochMs())',
        'if (!clock.instant().isBefore(entry.getValue().expiresAt()))')) {
    Assert-True ($federationRuntime.Contains($contract)) "product expiry lifecycle missing: $contract"
}
foreach ($contract in @('long issuedAt = clock.millis()',
        'long expiresAt = safeAdd(issuedAt, lifetimeMillis, "federation expiry overflow")')) {
    Assert-True ($federationDocuments.Contains($contract)) "product assertion timestamp missing: $contract"
}

$reportPropertyAssignment = Get-AssignmentAst $ast '$reportPropertyNames'
$validatorFunctions = (Get-FunctionText $platformAst @(
        'Get-JsonPropertyNames', 'Test-ExactJsonProperties', 'Test-JsonInteger')) + "`n`n" +
    (Get-FunctionText $ast @('ConvertFrom-StrictJson', 'Test-JsonString',
        'Test-JsonBoolean', 'Assert-PassingReportRaw', 'Assert-BindingRaw', 'Assert-CommitRaw'))

$hashes = @('1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')
$targetIndex = 0
foreach ($targetName in @($fabricTargets.Keys)) {
    $descriptor = $fabricTargets[$targetName]
    $quotedTarget = $targetName.Replace("'", "''")
    $quotedMinecraft = ([string]$descriptor.minecraft_version).Replace("'", "''")
    $quotedApi = ([string]$descriptor.fabric_api_version).Replace("'", "''")
    $quotedKind = ([string]$descriptor.artifact_kind).Replace("'", "''")
    $quotedMode = ([string]$descriptor.runtime_mode).Replace("'", "''")
    $validatorHeader = @"
Set-StrictMode -Version Latest
`$reportSchema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V2'
`$bindingSchema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V2'
`$commitSchema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V2'
`$artifactClass = 'sanitized-final-fabric-federation-gui-handoff'
`$MaximumReportAgeMinutes = 60
`$FabricTarget = '$quotedTarget'
`$fabricDescriptor = [ordered]@{
    minecraft_version = '$quotedMinecraft'
    fabric_api_version = '$quotedApi'
    artifact_kind = '$quotedKind'
    java_major = $([int]$descriptor.java_major)
    runtime_mode = '$quotedMode'
}
`$reportPropertyNames = $($reportPropertyAssignment.Right.Extent.Text)
"@
    $validator = New-Module -ScriptBlock ([scriptblock]::Create(
            $validatorHeader + "`n" + $validatorFunctions))
    try {
        $current = [ordered]@{
            wrapper_sha256 = ($hashes[0] * 64)
            wrapper_test_sha256 = ($hashes[1] * 64)
            platform_wrapper_sha256 = ($hashes[2] * 64)
            source_manifest_sha256 = ($hashes[3] * 64)
            source_file_count = 400
            fabric_target = $targetName
            minecraft_version = [string]$descriptor.minecraft_version
            fabric_api_version = [string]$descriptor.fabric_api_version
            fabric_artifact_kind = [string]$descriptor.artifact_kind
            fabric_java_major = [int]$descriptor.java_major
            fabric_runtime_mode = [string]$descriptor.runtime_mode
            server_matrix_manifest_sha256 = ($hashes[4] * 64)
            velocity_server_sha256 = ($hashes[5] * 64)
            bungee_server_sha256 = ($hashes[6] * 64)
            paper_server_sha256 = ($hashes[7] * 64)
            paper_prepared_manifest_sha256 = ($hashes[8] * 64)
            paper_prepared_tree_sha256 = ($hashes[9] * 64)
            paper_prepared_file_count = 100
            paper_prepared_total_size = [long]123456
            fabric_asset_cache_verified = $true
            fabric_version_info_sha1 = ('1' * 40)
            fabric_version_info_sha256 = ($hashes[10] * 64)
            fabric_asset_index_id = '26'
            fabric_asset_index_sha1 = ('2' * 40)
            fabric_asset_index_sha256 = ($hashes[11] * 64)
            fabric_asset_index_size = [long]654321
            fabric_asset_object_manifest_sha256 = ($hashes[12] * 64)
            fabric_asset_object_count = 200
            fabric_asset_object_total_size = [long]987654
            root_java_executable_sha256 = ($hashes[13] * 64)
            root_java_file_version = '21.0.8.0'
            target_java_executable_sha256 = ($hashes[14] * 64)
            target_java_file_version = if ([int]$descriptor.java_major -eq 25) { '25.0.0.0' } else { '21.0.8.0' }
            gradle_version = '9.6.1'
            gradle_launcher_sha256 = ('1' * 64)
            gradle_core_sha256 = ('2' * 64)
            fabric_artifact_sha256 = ('3' * 64)
            fabric_build_id = 'platform-smoke-20260820T000000000Z'
            velocity_plugin_sha256 = ('4' * 64)
            bungee_plugin_sha256 = ('5' * 64)
            paper_plugin_sha256 = ('6' * 64)
        }
        $report = [ordered]@{
            schema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V2'
            generated_at = [DateTimeOffset]::UtcNow.ToString('o')
            source_mode = 'EXECUTED_REAL_FABRIC_GUI'
            status = 'passed'
            artifact_class = 'sanitized-final-fabric-federation-gui-handoff'
            fabric_target = $targetName
            minecraft_version = [string]$descriptor.minecraft_version
            fabric_api_version = [string]$descriptor.fabric_api_version
            fabric_artifact_kind = [string]$descriptor.artifact_kind
            fabric_java_major = [int]$descriptor.java_major
            fabric_runtime_mode = [string]$descriptor.runtime_mode
            fabric_build_id = [string]$current.fabric_build_id
            fabric_codesource_sha256_observed = [string]$current.fabric_artifact_sha256
            source_proxy = 'VELOCITY'
            target_proxy = 'BUNGEE'
            federation_assertion_ttl_seconds = 120
            operator_human_attestation_count = 2
            human_visible_federation_consent_count = 2
            no_gui_automation = $true
            raw_peer_evidence_used = $false
            raw_content_retained = $false
            fabric_artifact_mode_verified = $true
            source_local_auth_verified = $true
            source_paper_admission_verified = $true
            source_export_consent_requested = $true
            source_export_consent_rendered = $true
            source_export_consent_allowed_once = $true
            source_grant_stored_memory_only = $true
            source_grant_ready_observed = $true
            source_disconnected_before_target_auth = $true
            target_local_auth_verified = $true
            target_import_consent_requested = $true
            target_import_consent_rendered = $true
            target_import_consent_allowed_once = $true
            presentation_sent = $true
            target_observation_recorded = $true
            target_subject_bound = $true
            target_observation_status_count_one = $true
            target_observation_status_one_before_expiry = $true
            target_paper_admission_verified = $true
            local_trust_risk_admission_unchanged = $true
            target_session_connected_through_expiry = $true
            observation_expired = $true
            target_observation_status_zero_after_expiry = $true
            client_shutdown_completed = $true
            cleanup_ports_free = $true
            remaining_owned_process_count = 0
            passed = $true
        }
        $reportRaw = $report | ConvertTo-Json -Depth 12 -Compress
        $validatedReport = & $validator {
            param($Json, $Binding)
            Assert-PassingReportRaw $Json $Binding 'VELOCITY' 'BUNGEE'
        } $reportRaw $current
        Assert-True ([bool]$validatedReport.passed) "valid V2 report rejected for $targetName"

        Assert-Throws {
            & $validator {
                param($Json, $Binding)
                Assert-PassingReportRaw $Json $Binding 'VELOCITY' 'BUNGEE'
            } "[$reportRaw]" $current
        } "top-level report array accepted for $targetName"
        $duplicateReportRaw = $reportRaw.Insert(1, '"passed":false,')
        Assert-Throws {
            & $validator {
                param($Json, $Binding)
                Assert-PassingReportRaw $Json $Binding 'VELOCITY' 'BUNGEE'
            } $duplicateReportRaw $current
        } "duplicate report property accepted for $targetName"

        Assert-ReportMutationRejected $validator $report $current 'schema' `
            'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V1' `
            "old V1 report accepted for $targetName"
        Assert-ReportMutationRejected $validator $report $current 'raw_peer_evidence_used' $true `
            "raw-peer evidence accepted for $targetName"
        Assert-ReportMutationRejected $validator $report $current 'operator_human_attestation_count' 1 `
            "one attestation can mint PASS for $targetName"
        Assert-ReportMutationRejected $validator $report $current 'target_import_consent_allowed_once' $false `
            "missing target GUI click can mint PASS for $targetName"
        Assert-ReportMutationRejected $validator $report $current 'target_paper_admission_verified' $false `
            "missing target Paper admission can mint PASS for $targetName"
        Assert-ReportMutationRejected $validator $report $current 'target_subject_bound' $false `
            "unbound target subject can mint PASS for $targetName"
        Assert-ReportMutationRejected $validator $report $current `
            'local_trust_risk_admission_unchanged' $false `
            "changed local state can mint PASS for $targetName"
        Assert-ReportMutationRejected $validator $report $current `
            'target_observation_status_one_before_expiry' $false `
            "missing pre-expiry observation can mint PASS for $targetName"
        Assert-ReportMutationRejected $validator $report $current `
            'target_session_connected_through_expiry' $false `
            "target disconnect can mint PASS for $targetName"
        Assert-ReportMutationRejected $validator $report $current 'observation_expired' $false `
            "unexpired observation can mint PASS for $targetName"
        Assert-ReportMutationRejected $validator $report $current `
            'target_observation_status_zero_after_expiry' $false `
            "nonzero expired observation can mint PASS for $targetName"
        Assert-ReportMutationRejected $validator $report $current 'cleanup_ports_free' $false `
            "port residue can mint PASS for $targetName"
        Assert-ReportMutationRejected $validator $report $current 'remaining_owned_process_count' 1 `
            "process residue can mint PASS for $targetName"
        Assert-ReportMutationRejected $validator $report $current 'fabric_codesource_sha256_observed' ('f' * 64) `
            "wrong final CodeSource SHA can mint PASS for $targetName"
        $wrongTarget = if ($targetName -ceq '1.21.11') { '26.1.2' } else { '1.21.11' }
        Assert-ReportMutationRejected $validator $report $current 'fabric_target' $wrongTarget `
            "cross-target report accepted for $targetName"

        $extraReport = Copy-JsonObject $report
        $extraReport | Add-Member -NotePropertyName raw_grant -NotePropertyValue 'forbidden'
        Assert-Throws {
            & $validator {
                param($Json, $Binding)
                Assert-PassingReportRaw $Json $Binding 'VELOCITY' 'BUNGEE'
            } ($extraReport | ConvertTo-Json -Depth 12 -Compress) $current
        } "extra/raw report property accepted for $targetName"

        $reportSha = Get-TextSha256 $reportRaw
        $binding = [ordered]@{
            schema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V2'
            report_schema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V2'
            report_generated_at = [string]$report.generated_at
            report_sha256 = $reportSha
            source_mode = 'EXECUTED_REAL_FABRIC_GUI'
            source_proxy = 'VELOCITY'
            target_proxy = 'BUNGEE'
            passed = $true
        }
        foreach ($entry in $current.GetEnumerator()) { $binding[$entry.Key] = $entry.Value }
        $bindingRaw = $binding | ConvertTo-Json -Depth 12 -Compress
        $validatedBinding = & $validator {
            param($Json, $Sha, $Report, $Current)
            Assert-BindingRaw $Json $Sha $Report $Current
        } $bindingRaw $reportSha $validatedReport $current
        Assert-True ([bool]$validatedBinding.passed) "valid V2 binding rejected for $targetName"

        Assert-Throws {
            & $validator {
                param($Json, $Sha, $Report, $Current)
                Assert-BindingRaw $Json $Sha $Report $Current
            } "[$bindingRaw]" $reportSha $validatedReport $current
        } "top-level binding array accepted for $targetName"
        $duplicateBindingRaw = $bindingRaw.Insert(1, '"passed":false,')
        Assert-Throws {
            & $validator {
                param($Json, $Sha, $Report, $Current)
                Assert-BindingRaw $Json $Sha $Report $Current
            } $duplicateBindingRaw $reportSha $validatedReport $current
        } "duplicate binding property accepted for $targetName"
        $arrayBinding = Copy-JsonObject $binding
        $arrayBinding.schema = @('MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V2')
        Assert-Throws {
            & $validator {
                param($Json, $Sha, $Report, $Current)
                Assert-BindingRaw $Json $Sha $Report $Current
            } ($arrayBinding | ConvertTo-Json -Depth 12 -Compress) `
                $reportSha $validatedReport $current
        } "single-element binding string array accepted for $targetName"

        foreach ($mutation in @(
                @('schema', 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V1', 'old V1 binding'),
                @('report_sha256', ('f' * 64), 'report/binding SHA mismatch'),
                @('fabric_target', $wrongTarget, 'cross-target binding'),
                @('fabric_artifact_sha256', ('f' * 64), 'artifact binding mismatch'))) {
            $badBinding = Copy-JsonObject $binding
            $badBinding.($mutation[0]) = $mutation[1]
            Assert-Throws {
                & $validator {
                    param($Json, $Sha, $Report, $Current)
                    Assert-BindingRaw $Json $Sha $Report $Current
                } ($badBinding | ConvertTo-Json -Depth 12 -Compress) $reportSha $validatedReport $current
            } "$($mutation[2]) accepted for $targetName"
        }

        $bindingSha = Get-TextSha256 $bindingRaw
        $commit = [ordered]@{
            schema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V2'
            report_schema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V2'
            binding_schema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V2'
            generated_at = [string]$report.generated_at
            report_sha256 = $reportSha
            binding_sha256 = $bindingSha
            fabric_target = $targetName
            source_proxy = 'VELOCITY'
            target_proxy = 'BUNGEE'
            passed = $true
        }
        $commitRaw = $commit | ConvertTo-Json -Depth 6 -Compress
        $validatedCommit = & $validator {
            param($Json, $ReportSha, $BindingSha, $Report)
            Assert-CommitRaw $Json $ReportSha $BindingSha $Report
        } $commitRaw $reportSha $bindingSha $validatedReport
        Assert-True ([bool]$validatedCommit.passed) "valid V2 commit rejected for $targetName"

        Assert-Throws {
            & $validator {
                param($Json, $ReportSha, $BindingSha, $Report)
                Assert-CommitRaw $Json $ReportSha $BindingSha $Report
            } "[$commitRaw]" $reportSha $bindingSha $validatedReport
        } "top-level commit array accepted for $targetName"
        $duplicateCommitRaw = $commitRaw.Insert(1, '"passed":false,')
        Assert-Throws {
            & $validator {
                param($Json, $ReportSha, $BindingSha, $Report)
                Assert-CommitRaw $Json $ReportSha $BindingSha $Report
            } $duplicateCommitRaw $reportSha $bindingSha $validatedReport
        } "duplicate commit property accepted for $targetName"
        $arrayCommit = Copy-JsonObject $commit
        $arrayCommit.schema = @('MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V2')
        Assert-Throws {
            & $validator {
                param($Json, $ReportSha, $BindingSha, $Report)
                Assert-CommitRaw $Json $ReportSha $BindingSha $Report
            } ($arrayCommit | ConvertTo-Json -Depth 6 -Compress) `
                $reportSha $bindingSha $validatedReport
        } "single-element commit string array accepted for $targetName"

        foreach ($mutation in @(
                @('schema', 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V1', 'old V1 commit'),
                @('report_sha256', ('f' * 64), 'commit report SHA mismatch'),
                @('binding_sha256', ('e' * 64), 'commit binding SHA mismatch'),
                @('fabric_target', $wrongTarget, 'cross-target commit'))) {
            $badCommit = Copy-JsonObject $commit
            $badCommit.($mutation[0]) = $mutation[1]
            Assert-Throws {
                & $validator {
                    param($Json, $ReportSha, $BindingSha, $Report)
                    Assert-CommitRaw $Json $ReportSha $BindingSha $Report
                } ($badCommit | ConvertTo-Json -Depth 6 -Compress) $reportSha $bindingSha $validatedReport
            } "$($mutation[2]) accepted for $targetName"
        }
    } finally {
        Remove-Module $validator -Force
    }
    $targetIndex++
}

Assert-True ($targetIndex -eq 3) 'dynamic validators did not cover all three Fabric targets'
Write-Output 'FABRIC_FEDERATION_GUI_HANDOFF_STATIC_V2_PASS'
