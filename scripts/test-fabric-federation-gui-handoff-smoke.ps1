[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$target = Join-Path $PSScriptRoot 'fabric-federation-gui-handoff-smoke.ps1'
$platformTarget = Join-Path $PSScriptRoot 'platform-load-smoke.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $target, [ref]$tokens, [ref]$errors)
$platformTokens = $null; $platformErrors = $null
$platformAst = [Management.Automation.Language.Parser]::ParseFile(
    $platformTarget, [ref]$platformTokens, [ref]$platformErrors)
if (@($errors).Count -ne 0 -or @($platformErrors).Count -ne 0) {
    throw "FABRIC_FEDERATION_GUI_V5_PARSE_FAILED|wrapper=$($errors -join '; ')|platform=$($platformErrors -join '; ')"
}
$source = [IO.File]::ReadAllText($target)
$rootFabricGradle = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\mcace-client-fabric\build.gradle.kts'))
$modernFabricGradle = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\fabric-modern\build.gradle.kts'))
$explicitConsentSource = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\fabric-modern\src\main\java\com\ellan\mcace\fabric\ExplicitFileConsentScreen.java'))
$evidenceConsentSource = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\fabric-modern\src\main\java\com\ellan\mcace\fabric\EvidenceConsentScreen.java'))

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "FABRIC_FEDERATION_GUI_V5_TEST_FAILED: $Message" }
}

function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $threw = $false
    try { & $Action } catch { $threw = $true }
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
        $mandatory = $false; $parameterSet = ''
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
    $attribute = @($parameter.Attributes | Where-Object {
        $_.TypeName.FullName -ceq 'ValidateSet'
    }) | Select-Object -First 1
    if ($null -eq $attribute) { return @() }
    return @($attribute.PositionalArguments | ForEach-Object {
        if ($_ -is [Management.Automation.Language.StringConstantExpressionAst]) {
            [string]$_.Value
        } else { $_.Extent.Text.Trim("'", '"') }
    })
}

function Get-AssignmentText(
        [Management.Automation.Language.Ast]$Root,
        [string]$VariableText) {
    $matches = @($Root.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq $VariableText
    }, $true))
    Assert-True ($matches.Count -eq 1) "$VariableText assignment is not unique"
    return $matches[0].Right.Extent.Text
}

function Get-FunctionText(
        [Management.Automation.Language.Ast]$Root,
        [string[]]$Names) {
    $parts = [Collections.Generic.List[string]]::new()
    foreach ($name in $Names) {
        $matches = @($Root.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $name
        }, $true))
        Assert-True ($matches.Count -eq 1) "function $name is not unique"
        $parts.Add($matches[0].Extent.Text)
    }
    return $parts -join "`n`n"
}

function Get-TestSha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function New-TestDocument([byte[]]$Bytes) {
    return [pscustomobject]@{
        raw = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        bytes = $Bytes
        sha256 = Get-TestSha256 $Bytes
        size_bytes = [long]$Bytes.Length
    }
}

function Copy-JsonObject([object]$Value) {
    $raw = $Value | ConvertTo-Json -Depth 12 -Compress
    $command = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
    if ($command.Parameters.ContainsKey('DateKind')) {
        return ConvertFrom-Json -InputObject $raw -DateKind String -ErrorAction Stop
    }
    return ConvertFrom-Json -InputObject $raw -ErrorAction Stop
}

# Exact public surface: production requires a gate-specific, out-of-band trust root and the
# protected release bundle. No caller-supplied PASS boolean or evidence output root is exposed.
$parameters = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
$expectedParameters = @(
    'Execute','ReportOnly','FabricTarget','SourceProxy','TargetProxy',
    'VisibleGuiSigningRequestPath','VisibleGuiAttestationPath','VisibleGuiScreenshotPath',
    'VisibleGuiTrustRootPath',
    'ExpectedVisibleGuiTrustRootSha256','PostRunSupervisorTrustRootPath',
    'ExpectedPostRunSupervisorTrustRootSha256','PostRunSigningRequestPath',
    'PostRunReceiptPath','ReleaseBundleRoot',
    'ExpectedFabricArtifactSha256','ExpectedVelocityPluginSha256',
    'ExpectedBungeePluginSha256','ExpectedPaperPluginSha256',
    'ExpectedVelocityServerSha256','ExpectedBungeeServerSha256','ExpectedPaperServerSha256',
    'ExpectedPaperPreparedManifestSha256','ExpectedPaperPreparedTreeSha256',
    'ExpectedFabricVersionInfoSha256','ExpectedFabricAssetIndexSha256',
    'ExpectedFabricAssetObjectManifestSha256','FederationAssertionTtlSeconds',
    'HumanTransitionTimeoutSeconds','PostRunReceiptTimeoutSeconds','MaximumReportAgeMinutes')
Assert-True ((($parameters | Sort-Object) -join '|') -ceq
    (($expectedParameters | Sort-Object) -join '|')) 'parameter surface is not exact'
Assert-True ($source -match "DefaultParameterSetName\s*=\s*'Disabled'") `
    'default parameter set must be disabled'
foreach ($name in @('FabricTarget','SourceProxy','TargetProxy','VisibleGuiTrustRootPath',
        'ExpectedVisibleGuiTrustRootSha256','PostRunSupervisorTrustRootPath',
        'ExpectedPostRunSupervisorTrustRootSha256','ReleaseBundleRoot')) {
    Assert-True (Test-MandatoryParameter $name 'Execute') "$name is not Execute-mandatory"
    Assert-True (Test-MandatoryParameter $name 'Report') "$name is not Report-mandatory"
}
foreach ($name in @('VisibleGuiSigningRequestPath','VisibleGuiAttestationPath','VisibleGuiScreenshotPath',
        'PostRunSigningRequestPath','PostRunReceiptPath')) {
    Assert-True (Test-MandatoryParameter $name 'Execute') "$name is not Execute-mandatory"
    Assert-True (-not (Test-MandatoryParameter $name 'Report')) "$name leaks into ReportOnly"
}
Assert-True (((Get-ValidateSet 'FabricTarget') -join ',') -ceq '1.21.11,26.1.2,26.2') `
    'three-version Fabric matrix changed'
foreach ($name in @('SourceProxy','TargetProxy')) {
    Assert-True (((Get-ValidateSet $name) -join ',') -ceq 'VELOCITY,BUNGEE') `
        "$name matrix changed"
}
foreach ($forbidden in @('EnablementHumanAttested','visible_computer_use_session',
        'ReportPath','BindingPath','CommitPath','EvidenceRoot','RunRoot','AllowTestFixture',
        'ApprovedVisibleGuiTrustRootSha256','ApprovedPostRunSupervisorTrustRootSha256')) {
    Assert-True ($forbidden -notin $parameters) "forge/pass parameter remains: $forbidden"
}

$requiredSchemas = @(
    'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V5',
    'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V5',
    'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V5',
    'MCACE_VISIBLE_GUI_SIGNING_REQUEST_V1','MCACE_VISIBLE_GUI_ATTESTATION_V3',
    'MCACE_VISIBLE_GUI_TRUST_ROOT_V1',
    'MCACE_FABRIC_FEDERATION_POSTRUN_RECEIPT_V1',
    'MCACE_FEDERATION_POSTRUN_TRUST_ROOT_V1',
    'MCACE_FABRIC_FEDERATION_RUNTIME_EVENT_V1','MCACE_RELEASE_BUNDLE_V4')
foreach ($schema in $requiredSchemas) {
    Assert-True $source.Contains($schema) "required V5 schema missing: $schema"
}
foreach ($obsolete in @(
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V4',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V4',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V4',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V3',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V3',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V3',
        'MCACE_VISIBLE_GUI_ATTESTATION_V1','MCACE_VISIBLE_GUI_ATTESTATION_V2',
        'MCACE_RELEASE_BUNDLE_V3')) {
    Assert-True (-not $source.Contains($obsolete)) "obsolete production schema remains: $obsolete"
}
foreach ($token in @(
        'FABRIC_FEDERATION_GUI_TRUST_ROOT_MUST_BE_OUT_OF_BAND',
        'FABRIC_FEDERATION_GUI_TEST_TRUST_ROOT_RELEASE_REJECTED',
        'FABRIC_FEDERATION_GUI_TEST_ATTESTATION_FIXTURE_RELEASE_REJECTED',
        'FABRIC_FEDERATION_GUI_TEST_POSTRUN_TRUST_ROOT_RELEASE_REJECTED',
        'FABRIC_FEDERATION_GUI_TEST_POSTRUN_RECEIPT_RELEASE_REJECTED',
        'MCACE_RELEASE_APPROVED_FEDERATION_GUI_TRUST_ROOT_SHA256',
        'MCACE_RELEASE_APPROVED_FEDERATION_POSTRUN_TRUST_ROOT_SHA256',
        'FABRIC_FEDERATION_GUI_APPROVED_SIGNER_PINS_MUST_DIFFER',
        'FABRIC_FEDERATION_GUI_SIGNER_KEYS_MUST_DIFFER',
        'FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_SIGNATURE_INVALID',
        'FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_BINDING_INVALID',
        'FABRIC_FEDERATION_GUI_REPORT_INVALID','FABRIC_FEDERATION_GUI_BINDING_INVALID',
        'FABRIC_FEDERATION_GUI_COMMIT_INVALID','FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_EVENT_INVALID',
        'RSA_PKCS1_SHA256','ExpectedChallengeIssuedAt','challenge_nonce',
        'MCACE_VISIBLE_GUI_SIGNING_REQUEST_CANONICAL_V1',
        'MCACE_VISIBLE_GUI_ATTESTATION_SIGNING_V3',
        'FABRIC_FEDERATION_GUI_SIGNING_REQUEST_EXPIRED_OR_TIME_INVALID',
        'FABRIC_FEDERATION_GUI_ATTESTATION_SIGNING_REQUEST_BINDING_INVALID',
        'prompt_challenge_visible','client_process_started_at','window_id',
        'FABRIC_FEDERATION_GUI_FINAL_RELEASE_JAR_RUNTIME_HASH_MISMATCH',
        'artifact_source_commit','runtime-events.jsonl','SUPERVISOR_SEALED',
        'SOURCE_SECOND_EXPORT_REQUESTED','SOURCE_SECOND_EXPORT_REJECTED',
        'SOURCE_SECOND_EXPORT_NO_GRANT_CONFIRMED','TARGET_INHERITED_EXPORT_REQUESTED',
        'TARGET_INHERITED_EXPORT_REJECTED','TARGET_INHERITED_EXPORT_NO_GRANT_CONFIRMED',
        'MCAceFederationFileIdentityV4','FILE_FLAG_OPEN_REPARSE_POINT',
        'GetFileInformationByHandle','decoded_pixel_sha256','Get-Crc32','Get-Adler32')) {
    Assert-True $source.Contains($token) "security contract token missing: $token"
}

# Release execution may configure/build launch infrastructure, but every runtime component must be
# copied from the protected bundle and the Fabric code source must preserve that JAR's exact bytes.
foreach ($contract in @(
        "Join-Path `$releaseBundleRuntimeRoot 'mcace-server-velocity.jar'",
        "Join-Path `$releaseBundleRuntimeRoot 'mcace-server-bungeecord.jar'",
        "Join-Path `$releaseBundleRuntimeRoot 'mcace-server-paper.jar'",
        '"mcace-client-fabric-$FabricTarget.jar"',
        'Start-FabricReleaseClient',
        "':mcace-client-fabric:runReleaseClient'",
        '"-PmcaceSmokeRuntimeArtifactPath=$fabricArtifactJar"',
        'FABRIC_FEDERATION_GUI_FINAL_RELEASE_SERVER_RUNTIME_HASH_MISMATCH')) {
    Assert-True $source.Contains($contract) "exact release runtime contract missing: $contract"
}
foreach ($forbiddenRuntimeSource in @(
        'mcace-server-velocity-0.1.0-SNAPSHOT.jar',
        'mcace-server-bungeecord-0.1.0-SNAPSHOT.jar',
        'mcace-server-paper-0.1.0-SNAPSHOT.jar',
        ':mcace-server-velocity:shadowJar',
        ':mcace-server-bungeecord:shadowJar',
        ':mcace-server-paper:shadowJar')) {
    Assert-True (-not $source.Contains($forbiddenRuntimeSource)) `
        "snapshot runtime source remains: $forbiddenRuntimeSource"
}
$releaseStarter = Get-FunctionText $ast @('Start-FabricReleaseClient')
Assert-True (-not $releaseStarter.Contains('Start-FabricClient')) `
    'release client delegates to the development snapshot launcher'
# The shared root dependency stage evaluates the legacy 1.21.11 project even when the
# requested runtime is 26.x.  It must therefore use a legacy-valid smoke identity while
# the isolated modern verification keeps the protected target release identity.
Assert-True ($source.Contains('$rootStageProperties = @(')) `
    'modern federation stage does not define a legacy-valid root property set'
Assert-True ($source.Contains('"-PmcaceClientBuildId=platform-smoke-$runId"')) `
    'root dependency stage lost its platform-smoke build identity'
Assert-True ($source.Contains('        $rootStageProperties $true') -and
    $source.Contains('FABRIC_FEDERATION_GUI_ROOT_JDK21_BUILD_FAILED')) `
    'root dependency stage is not using the legacy-valid property set'
Assert-True ($source.Contains('    $modernProperties = @($smokeBuildProperties) + @(')) `
    'modern verification no longer retains the protected release property set'
Assert-True ($explicitConsentSource -notmatch '(?m)^\s*extractBackground\s*\(') `
    'explicit consent screen must not extract the background a second time'
Assert-True ($evidenceConsentSource -notmatch '(?m)^\s*extractBackground\s*\(') `
    'evidence consent screen must not extract the background a second time'
foreach ($contract in @(
        'val smokeRuntimeArtifactPath',
        'runReleaseClient',
        'net.fabricmc.loader.impl.launch.knot.KnotClient',
        'fabric.development", "false',
        'net.fabricmc:intermediary:1.21.11:v2',
        'runtimeArtifact.copyTo(runtimeCopy, overwrite = false)',
        'sha256(runtimeCopy) == expectedArtifactSha256',
        'requires an existing empty dedicated mods directory')) {
    Assert-True $rootFabricGradle.Contains($contract) `
        "1.21.11 exact production runtime contract missing: $contract"
}
foreach ($contract in @(
        'val smokeRuntimeArtifactPath',
        'val exactReleaseRuntimeMode',
        'modFiles.setFrom(smokeRuntimeArtifact)',
        'plus(files(smokeRuntimeArtifact))',
        'mcace.client.enablement-decision-timeout-seconds',
        'sha256(artifact) == expectedArtifactSha256')) {
    Assert-True $modernFabricGradle.Contains($contract) `
        "modern exact named runtime contract missing: $contract"
}
$evidenceDirectoryValidator = Get-FunctionText $ast @('Assert-ExactFederationEvidenceDirectory')
foreach ($name in @('binding.json','commit.json','report.json','runtime-events.jsonl',
        'visible-gui-attestation.json','visible-gui-signing-request.json','visible-gui.png',
        'post-run-receipt.json')) {
    Assert-True $evidenceDirectoryValidator.Contains("'$name'") `
        "eight-file final evidence set is missing $name"
}
Assert-True ($source.Contains('[int]$report.runtime_ledger_event_count -ne 18')) `
    'runtime ledger is not an exact event-set gate'
$guiExchangeBlock = Get-FunctionText $ast @(
    'Get-CanonicalExchangePathBinding','Assert-VisibleGuiSigningRequest',
    'Assert-VisibleGuiAttestation')
foreach ($contract in @(
        'signing_request_path_sha256','screenshot_path_sha256',
        'screenshot_freeze_mode',
        'attestation_output_path_sha256','attestation_payload_format',
        'attestation_publish_mode',
        'artifact_source_commit','gui_attempt_id',
        'request_created_at','expires_at','signing_request_sha256')) {
    Assert-True $guiExchangeBlock.Contains($contract) `
        "canonical GUI exchange binding missing: $contract"
}
foreach ($contract in @(
        'Write-NewLockedJsonExchange',
        'Assert-LockedFileIdentity $visibleGuiSigningRequestOutput')) {
    Assert-True $source.Contains($contract) "GUI request atomic/no-follow contract missing: $contract"
}

# Build an isolated copy of the actual production validators. This keeps the fixture tests tied to
# the code that runs in Execute/ReportOnly rather than testing a weaker duplicate parser.
$platformFunctions = Get-FunctionText $platformAst @(
    'Get-BytesSha256','Get-JsonPropertyNames','Test-ExactJsonProperties',
    'Test-JsonInteger','Assert-DirectLocalPath')
$wrapperFunctions = Get-FunctionText $ast @(
    'ConvertFrom-StrictJson','Test-IsWindowsPlatform','Initialize-WindowsFileIdentityApi',
    'Get-NoFollowFileIdentity','Assert-LockedFileIdentity','Assert-SanitizedJson',
    'Write-NewLockedJsonExchange','Open-LockedFileBytes',
    'Get-Crc32','Get-Adler32','Expand-PngZlib','Get-PaethPredictor','Get-PngUInt32',
    'Assert-PngEvidence','Test-JsonString','Test-JsonBoolean','Test-Sha256',
    'Get-CanonicalExchangePathBinding','Assert-VisibleGuiSigningRequest',
    'Get-VisibleGuiAttestationSigningPayload','Assert-VisibleGuiTrustRoot',
    'Test-RsaPkcs1Sha256Signature','Assert-VisibleGuiAttestation',
    'Get-ApprovedReleaseSignerPin','Get-PostRunReceiptSigningPayload',
    'Assert-PostRunSupervisorTrustRoot','Assert-DistinctFederationSignerRoots',
    'Assert-PostRunReceipt',
    'Read-StrictPropertiesBytes','Get-ReleaseBundleTargetBinding',
    'Get-ProcessStartTimeString','Get-ProcessIncarnationId','Get-RuntimeEventSigningPayload',
    'New-RuntimeLedger','Add-RuntimeLedgerEvent','Complete-RuntimeLedger',
    'Assert-RuntimeLedgerBytes','Assert-PassingReportRaw','Assert-BindingRaw',
    'Assert-CommitRaw','Assert-ExactFederationEvidenceDirectory')
$validatorHeader = @"
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
`$reportSchema = $(Get-AssignmentText $ast '$reportSchema')
`$bindingSchema = $(Get-AssignmentText $ast '$bindingSchema')
`$commitSchema = $(Get-AssignmentText $ast '$commitSchema')
`$visibleGuiSigningRequestSchema = $(Get-AssignmentText $ast '$visibleGuiSigningRequestSchema')
`$visibleGuiSigningRequestDomain = $(Get-AssignmentText $ast '$visibleGuiSigningRequestDomain')
`$visibleGuiAttestationSchema = $(Get-AssignmentText $ast '$visibleGuiAttestationSchema')
`$visibleGuiAttestationSigningDomain = $(Get-AssignmentText $ast '$visibleGuiAttestationSigningDomain')
`$visibleGuiTrustRootSchema = $(Get-AssignmentText $ast '$visibleGuiTrustRootSchema')
`$postRunReceiptSchema = $(Get-AssignmentText $ast '$postRunReceiptSchema')
`$postRunTrustRootSchema = $(Get-AssignmentText $ast '$postRunTrustRootSchema')
`$runtimeEventSchema = $(Get-AssignmentText $ast '$runtimeEventSchema')
`$visibleGuiAttestationArtifactClass = $(Get-AssignmentText $ast '$visibleGuiAttestationArtifactClass')
`$visibleGuiAttestationSourceMode = $(Get-AssignmentText $ast '$visibleGuiAttestationSourceMode')
`$visibleGuiSigningRequestArtifactClass = $(Get-AssignmentText $ast '$visibleGuiSigningRequestArtifactClass')
`$visibleGuiSigningRequestSourceMode = $(Get-AssignmentText $ast '$visibleGuiSigningRequestSourceMode')
`$postRunReceiptArtifactClass = $(Get-AssignmentText $ast '$postRunReceiptArtifactClass')
`$artifactClass = $(Get-AssignmentText $ast '$artifactClass')
`$visibleGuiAttestationPropertyNames = $(Get-AssignmentText $ast '$visibleGuiAttestationPropertyNames')
`$visibleGuiSigningRequestPropertyNames = $(Get-AssignmentText $ast '$visibleGuiSigningRequestPropertyNames')
`$visibleGuiTrustRootPropertyNames = $(Get-AssignmentText $ast '$visibleGuiTrustRootPropertyNames')
`$postRunTrustRootPropertyNames = $(Get-AssignmentText $ast '$postRunTrustRootPropertyNames')
`$postRunReceiptPropertyNames = $(Get-AssignmentText $ast '$postRunReceiptPropertyNames')
`$runtimeEventPropertyNames = $(Get-AssignmentText $ast '$runtimeEventPropertyNames')
`$reportPropertyNames = $(Get-AssignmentText $ast '$reportPropertyNames')
"@
$validator = New-Module -ScriptBlock ([scriptblock]::Create(
    $validatorHeader + "`n" + $platformFunctions + "`n" + $wrapperFunctions))

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('mcace-federation-v5-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($tempRoot) | Out-Null
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$symlinkCovered = $false
$rsa = $null
$postRunRsa = $null
$unapprovedPostRunRsa = $null
$atomicExchangeEvidence = $null
try {
    # A real PNG encoder creates IHDR/IDAT/IEND and valid CRC/zlib/Adler data. The challenge is
    # rendered into the image as well as bound into the signed receipt.
    Add-Type -AssemblyName System.Drawing
    $challenge = '0123456789abcdef' * 4
    $attempt = 'a1' * 16
    $guiAttempt = 'e2' * 16
    $sourceCommit = 'b' * 40
    $targetVersion = '26.2'
    $finalJarSha = 'c' * 64
    $pngPath = Join-Path $tempRoot 'visible-gui.png'
    $bitmap = [Drawing.Bitmap]::new(640, 360)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    $font = [Drawing.Font]::new('Arial', 18)
    try {
        $graphics.Clear([Drawing.Color]::FromArgb(24, 29, 38))
        $graphics.DrawString('MCAce real prompt fixture', $font, [Drawing.Brushes]::White, 24, 28)
        $graphics.DrawString("challenge=$challenge", $font, [Drawing.Brushes]::Lime, 24, 90)
        $graphics.DrawString("attempt=$attempt", $font, [Drawing.Brushes]::Cyan, 24, 150)
        $bitmap.Save($pngPath, [Drawing.Imaging.ImageFormat]::Png)
    } finally { $font.Dispose(); $graphics.Dispose(); $bitmap.Dispose() }
    $pngBytes = [IO.File]::ReadAllBytes($pngPath)
    $pngDoc = [pscustomobject]@{
        bytes=$pngBytes; sha256=Get-TestSha256 $pngBytes; size_bytes=[long]$pngBytes.Length
    }
    $png = & $validator { param($Bytes) Assert-PngEvidence $Bytes } $pngBytes
    Assert-True ([int]$png.width -eq 640 -and [int]$png.height -eq 360) `
        'real PNG did not fully decode'
    Assert-True ([string]$png.decoded_pixel_sha256 -cmatch '^[0-9a-f]{64}$') `
        'decoded pixel hash missing'
    $crcTampered = [byte[]]$pngBytes.Clone(); $crcTampered[40] = $crcTampered[40] -bxor 1
    Assert-Throws { $null = & $validator { param($Bytes) Assert-PngEvidence $Bytes } $crcTampered } `
        'CRC-tampered PNG passed'
    $truncated = New-Object byte[] ($pngBytes.Length - 12)
    [Array]::Copy($pngBytes, 0, $truncated, 0, $truncated.Length)
    Assert-Throws { $null = & $validator { param($Bytes) Assert-PngEvidence $Bytes } $truncated } `
        'PNG without IEND passed'

    # Fixture keys are usable only under the parser-test switch; the production path explicitly
    # rejects the same correctly signed receipt and key.
    $rsa = [Security.Cryptography.RSACryptoServiceProvider]::new(2048)
    $rsa.PersistKeyInCsp = $false
    $public = $rsa.ExportParameters($false)
    $trustRoot = [ordered]@{
        schema='MCACE_VISIBLE_GUI_TRUST_ROOT_V1'
        artifact_class='TEST_GUI_SIGNING_TRUST_ROOT_FIXTURE'
        key_id='fixture-gui-signing-key-01'
        algorithm='RSA_PKCS1_SHA256'
        modulus_base64=[Convert]::ToBase64String($public.Modulus)
        exponent_base64=[Convert]::ToBase64String($public.Exponent)
        test_fixture=$true
    }
    $trustBytes = $utf8NoBom.GetBytes(($trustRoot | ConvertTo-Json -Compress))
    $trustDoc = New-TestDocument $trustBytes
    $challengeIssued = [DateTimeOffset]::UtcNow.AddSeconds(-8)
    $clientStarted = [DateTimeOffset]::UtcNow.AddSeconds(-7)
    $prompt = [DateTimeOffset]::UtcNow.AddSeconds(-6)
    $captured = [DateTimeOffset]::UtcNow.AddSeconds(-4)
    $requestCreated = [DateTimeOffset]::UtcNow.AddMilliseconds(-3500)
    $signed = [DateTimeOffset]::UtcNow.AddSeconds(-3)
    $accepted = [DateTimeOffset]::UtcNow.AddSeconds(-2)
    $requestExpires = [DateTimeOffset]::UtcNow.AddSeconds(60)
    $requestPath = Join-Path $tempRoot 'visible-gui-signing-request.json'
    $attestationPath = Join-Path $tempRoot 'visible-gui-attestation.json'
    $requestPathBinding = & $validator {
        param($Path) Get-CanonicalExchangePathBinding $Path
    } $requestPath
    $screenshotPathBinding = & $validator {
        param($Path) Get-CanonicalExchangePathBinding $Path
    } $pngPath
    $attestationPathBinding = & $validator {
        param($Path) Get-CanonicalExchangePathBinding $Path
    } $attestationPath
    $request = [ordered]@{
        schema='MCACE_VISIBLE_GUI_SIGNING_REQUEST_V1'
        domain='MCACE_VISIBLE_GUI_SIGNING_REQUEST_CANONICAL_V1'
        artifact_class='TEST_VISIBLE_GUI_SIGNING_REQUEST_FIXTURE'
        source_mode='TEST_NOFOLLOW_ATOMIC_EXCHANGE_FIXTURE'
        attestation_schema='MCACE_VISIBLE_GUI_ATTESTATION_V3'
        attestation_artifact_class='TEST_SIGNED_GUI_ATTESTATION_FIXTURE'
        attestation_source_mode='TEST_SIGNED_PARSER_FIXTURE'
        attestation_tool='computer-use'
        attestation_signing_domain='MCACE_VISIBLE_GUI_ATTESTATION_SIGNING_V3'
        attestation_payload_format='LF_KEY_EQUALS_VALUE_UTF8_FINAL_LF_V1'
        attestation_property_order_csv=(& $validator {
            $visibleGuiAttestationPropertyNames -join ','
        })
        attestation_required_assertions='prompt_challenge_visible=true,operator_attested_visible_session=true,operator_attested_no_headless_or_synthetic_input=true'
        attestation_publish_mode='ATOMIC_CREATE_NEW_COMPLETE_JSON_THEN_CLOSE_V1'
        attestation_test_fixture=$true
        source_commit=$sourceCommit
        artifact_source_commit=$sourceCommit
        product_version='0.0.1'
        fabric_target=$targetVersion
        source_proxy='VELOCITY'
        target_proxy='BUNGEE'
        release_bundle_manifest_sha256=('d' * 64)
        final_fabric_jar_file='mcace-client-fabric-26.2.jar'
        final_fabric_jar_sha256=$finalJarSha
        final_fabric_jar_size_bytes=1048576L
        client_build_id="fabric-$targetVersion-$sourceCommit"
        run_attempt_id=$attempt
        gui_attempt_id=$guiAttempt
        challenge_nonce=$challenge
        challenge_issued_at=$challengeIssued.ToString('o')
        prompt_rendered_at=$prompt.ToString('o')
        request_created_at=$requestCreated.ToString('o')
        expires_at=$requestExpires.ToString('o')
        client_process_id=43210
        client_process_started_at=$clientStarted.ToString('o')
        path_canonicalization=[string]$requestPathBinding.canonicalization
        signing_request_file='visible-gui-signing-request.json'
        signing_request_path_sha256=[string]$requestPathBinding.sha256
        screenshot_file='visible-gui.png'
        screenshot_path_sha256=[string]$screenshotPathBinding.sha256
        screenshot_freeze_mode='PRECLICK_FILESHARE_READ_LOCK_UNTIL_ACCEPT_V1'
        screenshot_sha256=[string]$pngDoc.sha256
        screenshot_size_bytes=[long]$pngDoc.size_bytes
        screenshot_width=[int]$png.width
        screenshot_height=[int]$png.height
        screenshot_decoded_pixel_sha256=[string]$png.decoded_pixel_sha256
        attestation_output_file='visible-gui-attestation.json'
        attestation_output_path_sha256=[string]$attestationPathBinding.sha256
        signer_key_id='fixture-gui-signing-key-01'
        signer_trust_root_sha256=[string]$trustDoc.sha256
        signature_algorithm='RSA_PKCS1_SHA256'
        test_fixture=$true
    }
    $requestBytes = $utf8NoBom.GetBytes(($request | ConvertTo-Json -Compress))
    $requestDoc = New-TestDocument $requestBytes
    $atomicExchangePath = Join-Path $tempRoot 'atomic-visible-gui-signing-request.json'
    $atomicExchangeEvidence = & $validator {
        param($Path,$Content) Write-NewLockedJsonExchange $Path $Content
    } $atomicExchangePath ($request | ConvertTo-Json -Compress)
    Assert-True ([string]$atomicExchangeEvidence.sha256 -ceq [string]$requestDoc.sha256) `
        'atomic GUI signing request bytes changed during create/readback'
    Assert-Throws {
        Move-Item -LiteralPath $atomicExchangePath `
            -Destination (Join-Path $tempRoot 'replacement-request.json') -ErrorAction Stop
    } 'locked GUI signing request path replacement succeeded'
    $atomicExchangeEvidence.stream.Dispose()
    $atomicExchangeEvidence = $null
    $validatedRequest = & $validator {
        param($Evidence,$Screenshot,$Expected,$Current)
        Assert-VisibleGuiSigningRequest $Evidence $Screenshot $Expected $Current -AllowTestFixture
    } $requestDoc $pngDoc $request $signed
    Assert-True ([string]$validatedRequest.sha256 -ceq [string]$requestDoc.sha256) `
        'canonical GUI signing request failed positive validation'

    $missingRequest = Copy-JsonObject ([pscustomobject]$request)
    $missingRequest.PSObject.Properties.Remove('gui_attempt_id')
    $missingRequestDoc = New-TestDocument `
        ($utf8NoBom.GetBytes(($missingRequest | ConvertTo-Json -Compress)))
    Assert-Throws {
        $null = & $validator {
            param($Evidence,$Screenshot,$Expected,$Current)
            Assert-VisibleGuiSigningRequest $Evidence $Screenshot $Expected $Current -AllowTestFixture
        } $missingRequestDoc $pngDoc $request $signed
    } 'GUI signing request missing field passed'
    $tamperedRequest = Copy-JsonObject ([pscustomobject]$request)
    $tamperedRequest.final_fabric_jar_sha256 = 'f' * 64
    $tamperedRequestDoc = New-TestDocument `
        ($utf8NoBom.GetBytes(($tamperedRequest | ConvertTo-Json -Compress)))
    Assert-Throws {
        $null = & $validator {
            param($Evidence,$Screenshot,$Expected,$Current)
            Assert-VisibleGuiSigningRequest $Evidence $Screenshot $Expected $Current -AllowTestFixture
        } $tamperedRequestDoc $pngDoc $request $signed
    } 'tampered GUI signing request passed'
    $replayExpected = [ordered]@{}
    foreach ($name in $request.Keys) { $replayExpected[$name] = $request[$name] }
    $replayExpected.gui_attempt_id = '91' * 16
    Assert-Throws {
        $null = & $validator {
            param($Evidence,$Screenshot,$Expected,$Current)
            Assert-VisibleGuiSigningRequest $Evidence $Screenshot $Expected $Current -AllowTestFixture
        } $requestDoc $pngDoc $replayExpected $signed
    } 'replayed GUI signing request passed a new GUI attempt'
    Assert-Throws {
        $null = & $validator {
            param($Evidence,$Screenshot,$Expected,$Current)
            Assert-VisibleGuiSigningRequest $Evidence $Screenshot $Expected $Current -AllowTestFixture
        } $requestDoc $pngDoc $request $requestExpires.AddTicks(1)
    } 'expired GUI signing request passed'
    $replacementExpected = [ordered]@{}
    foreach ($name in $request.Keys) { $replacementExpected[$name] = $request[$name] }
    $replacementBinding = & $validator {
        param($Path) Get-CanonicalExchangePathBinding $Path
    } (Join-Path $tempRoot 'replacement-visible-gui.png')
    $replacementExpected.screenshot_path_sha256 = [string]$replacementBinding.sha256
    Assert-Throws {
        $null = & $validator {
            param($Evidence,$Screenshot,$Expected,$Current)
            Assert-VisibleGuiSigningRequest $Evidence $Screenshot $Expected $Current -AllowTestFixture
        } $requestDoc $pngDoc $replacementExpected $signed
    } 'GUI signing request path replacement passed'

    $attestation = [ordered]@{
        schema='MCACE_VISIBLE_GUI_ATTESTATION_V3'
        artifact_class='TEST_SIGNED_GUI_ATTESTATION_FIXTURE'
        source_mode='TEST_SIGNED_PARSER_FIXTURE'
        tool='computer-use'
        session_id='fixture-session-01'
        window_id='0x1234'
        client_process_id=43210
        client_process_started_at=$clientStarted.ToString('o')
        attempt_id=$attempt
        gui_attempt_id=$guiAttempt
        challenge_nonce=$challenge
        challenge_issued_at=$challengeIssued.ToString('o')
        captured_at=$captured.ToString('o')
        signed_at=$signed.ToString('o')
        source_commit=$sourceCommit
        fabric_target=$targetVersion
        final_fabric_jar_sha256=$finalJarSha
        signing_request_schema='MCACE_VISIBLE_GUI_SIGNING_REQUEST_V1'
        signing_request_sha256=[string]$requestDoc.sha256
        screenshot_file='visible-gui.png'
        screenshot_sha256=[string]$pngDoc.sha256
        screenshot_size_bytes=[long]$pngDoc.size_bytes
        screenshot_width=[int]$png.width
        screenshot_height=[int]$png.height
        screenshot_decoded_pixel_sha256=[string]$png.decoded_pixel_sha256
        prompt_challenge_visible=$true
        operator_attested_visible_session=$true
        operator_attested_no_headless_or_synthetic_input=$true
        signer_key_id='fixture-gui-signing-key-01'
        signer_trust_root_sha256=[string]$trustDoc.sha256
        signature_algorithm='RSA_PKCS1_SHA256'
        test_fixture=$true
        signature_base64=''
    }
    $signingPayload = & $validator {
        param($Value) Get-VisibleGuiAttestationSigningPayload $Value
    } ([pscustomobject]$attestation)
    $attestation.signature_base64 = [Convert]::ToBase64String($rsa.SignData($signingPayload, 'SHA256'))
    $attestationBytes = $utf8NoBom.GetBytes(($attestation | ConvertTo-Json -Compress))
    $attestationDoc = New-TestDocument $attestationBytes
    $validated = & $validator {
        param($Evidence,$Screenshot,$Request,$ValidatedRequest,$Trust,$TrustSha,$Prompt,$Accepted,
            $Commit,$Target,$Jar,$Attempt,$GuiAttempt,$Challenge,$Issued,$ProcessId,$Started,$Approved)
        Assert-VisibleGuiAttestation $Evidence $Screenshot $Request $ValidatedRequest `
            $Trust $TrustSha $Prompt $Accepted $Commit $Target $Jar $Attempt $GuiAttempt `
            $Challenge $Issued $ProcessId $Started $Approved `
            -AllowTestFixture
    } $attestationDoc $pngDoc $requestDoc $validatedRequest $trustDoc $trustDoc.sha256 `
        $prompt $accepted $sourceCommit $targetVersion $finalJarSha $attempt $guiAttempt `
        $challenge $challengeIssued 43210 `
        $clientStarted.ToString('o') $trustDoc.sha256
    Assert-True ([string]$validated.trust_root_key_id -ceq 'fixture-gui-signing-key-01') `
        'valid signed fixture failed'
    Assert-Throws {
        $null = & $validator {
            param($Evidence,$Screenshot,$Request,$ValidatedRequest,$Trust,$TrustSha,$Prompt,$Accepted,
                $Commit,$Target,$Jar,$Attempt,$GuiAttempt,$Challenge,$Issued,$ProcessId,$Started,$Approved)
            Assert-VisibleGuiAttestation $Evidence $Screenshot $Request $ValidatedRequest `
                $Trust $TrustSha $Prompt $Accepted $Commit $Target $Jar $Attempt $GuiAttempt `
                $Challenge $Issued $ProcessId $Started $Approved
        } $attestationDoc $pngDoc $requestDoc $validatedRequest $trustDoc $trustDoc.sha256 `
            $prompt $accepted $sourceCommit $targetVersion $finalJarSha $attempt $guiAttempt `
            $challenge $challengeIssued 43210 `
            $clientStarted.ToString('o') $trustDoc.sha256
    } 'fixture trust root or receipt passed the release path'
    Assert-Throws {
        $null = & $validator {
            param($Evidence,$Screenshot,$Request,$ValidatedRequest,$Trust,$TrustSha,$Prompt,$Accepted,
                $Commit,$Target,$Jar,$Attempt,$GuiAttempt,$Challenge,$Issued,$ProcessId,$Started,$Approved)
            Assert-VisibleGuiAttestation $Evidence $Screenshot $Request $ValidatedRequest `
                $Trust $TrustSha $Prompt $Accepted $Commit $Target $Jar $Attempt $GuiAttempt `
                $Challenge $Issued $ProcessId $Started $Approved `
                -AllowTestFixture
        } $attestationDoc $pngDoc $requestDoc $validatedRequest $trustDoc $trustDoc.sha256 `
            $prompt $accepted $sourceCommit $targetVersion $finalJarSha $attempt $guiAttempt `
            $challenge $challengeIssued 43210 `
            $clientStarted.ToString('o') ('0' * 64)
    } 'self-consistent GUI fixture not approved by the frozen pin passed'
    $badChallenge = Copy-JsonObject ([pscustomobject]$attestation)
    $badChallenge.challenge_nonce = 'd' * 64
    $badChallenge.signature_base64 = ''
    $badPayload = & $validator { param($Value) Get-VisibleGuiAttestationSigningPayload $Value } $badChallenge
    $badChallenge.signature_base64 = [Convert]::ToBase64String($rsa.SignData($badPayload, 'SHA256'))
    $badChallengeDoc = New-TestDocument ($utf8NoBom.GetBytes(($badChallenge | ConvertTo-Json -Compress)))
    Assert-Throws {
        $null = & $validator {
            param($Evidence,$Screenshot,$Request,$ValidatedRequest,$Trust,$TrustSha,$Prompt,$Accepted,
                $Commit,$Target,$Jar,$Attempt,$GuiAttempt,$Challenge,$Issued,$ProcessId,$Started,$Approved)
            Assert-VisibleGuiAttestation $Evidence $Screenshot $Request $ValidatedRequest `
                $Trust $TrustSha $Prompt $Accepted $Commit $Target $Jar $Attempt $GuiAttempt `
                $Challenge $Issued $ProcessId $Started $Approved `
                -AllowTestFixture
        } $badChallengeDoc $pngDoc $requestDoc $validatedRequest $trustDoc $trustDoc.sha256 `
            $prompt $accepted $sourceCommit $targetVersion $finalJarSha $attempt $guiAttempt `
            $challenge $challengeIssued 43210 `
            $clientStarted.ToString('o') $trustDoc.sha256
    } 'differently signed challenge passed expected nonce binding'
    $badRequestHash = Copy-JsonObject ([pscustomobject]$attestation)
    $badRequestHash.signing_request_sha256 = '8' * 64
    $badRequestHash.signature_base64 = ''
    $badRequestPayload = & $validator {
        param($Value) Get-VisibleGuiAttestationSigningPayload $Value
    } $badRequestHash
    $badRequestHash.signature_base64 = [Convert]::ToBase64String(
        $rsa.SignData($badRequestPayload, 'SHA256'))
    $badRequestHashDoc = New-TestDocument `
        ($utf8NoBom.GetBytes(($badRequestHash | ConvertTo-Json -Compress)))
    Assert-Throws {
        $null = & $validator {
            param($Evidence,$Screenshot,$Request,$ValidatedRequest,$Trust,$TrustSha,$Prompt,$Accepted,
                $Commit,$Target,$Jar,$Attempt,$GuiAttempt,$Challenge,$Issued,$ProcessId,$Started,$Approved)
            Assert-VisibleGuiAttestation $Evidence $Screenshot $Request $ValidatedRequest `
                $Trust $TrustSha $Prompt $Accepted $Commit $Target $Jar $Attempt $GuiAttempt `
                $Challenge $Issued $ProcessId $Started $Approved -AllowTestFixture
        } $badRequestHashDoc $pngDoc $requestDoc $validatedRequest $trustDoc $trustDoc.sha256 `
            $prompt $accepted $sourceCommit $targetVersion $finalJarSha $attempt $guiAttempt `
            $challenge $challengeIssued 43210 $clientStarted.ToString('o') $trustDoc.sha256
    } 'attestation signed over a substituted GUI request hash passed'
    $badSignature = Copy-JsonObject ([pscustomobject]$attestation)
    $signatureBytes = [Convert]::FromBase64String([string]$badSignature.signature_base64)
    $signatureBytes[0] = $signatureBytes[0] -bxor 1
    $badSignature.signature_base64 = [Convert]::ToBase64String($signatureBytes)
    $badSignatureDoc = New-TestDocument ($utf8NoBom.GetBytes(($badSignature | ConvertTo-Json -Compress)))
    Assert-Throws {
        $null = & $validator {
            param($Evidence,$Screenshot,$Request,$ValidatedRequest,$Trust,$TrustSha,$Prompt,$Accepted,
                $Commit,$Target,$Jar,$Attempt,$GuiAttempt,$Challenge,$Issued,$ProcessId,$Started,$Approved)
            Assert-VisibleGuiAttestation $Evidence $Screenshot $Request $ValidatedRequest `
                $Trust $TrustSha $Prompt $Accepted $Commit $Target $Jar $Attempt $GuiAttempt `
                $Challenge $Issued $ProcessId $Started $Approved `
                -AllowTestFixture
        } $badSignatureDoc $pngDoc $requestDoc $validatedRequest $trustDoc $trustDoc.sha256 `
            $prompt $accepted $sourceCommit $targetVersion $finalJarSha $attempt $guiAttempt `
            $challenge $challengeIssued 43210 `
            $clientStarted.ToString('o') $trustDoc.sha256
    } 'tampered RSA signature passed'

    # Construct the exact append-only runtime event sequence through the production append writer.
    function New-LedgerFixture([string]$Path, [bool]$BadSourceCorrelation) {
        $run = '1f' * 16
        $sourceConnection = '2a' * 16
        $targetConnection = '3b' * 16
        $session = '4c' * 16
        $sourceOperation = '5d' * 16
        $targetOperation = '6e' * 16
        $subject = '7f' * 32
        $started = [DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o')
        $ledger = & $validator {
            param($P,$Run,$Commit,$Target) New-RuntimeLedger $P $Run $Commit $Target
        } $Path $run $sourceCommit $targetVersion
        function Add([string]$Type,[string]$Operation,[string]$Role,[int]$ProcessId,
                [string]$Peer,[string]$Connection,[string]$Session,[string]$Subject,[string]$Marker) {
            $markerHash = Get-TestSha256 ($utf8NoBom.GetBytes($Marker))
            $null = & $validator {
                param($Ledger,$Type,$Operation,$Role,$ProcessId,$Started,$Peer,$Connection,$Session,$Subject,$Marker)
                Add-RuntimeLedgerEvent $Ledger $Type $Operation $Role $ProcessId $Started $Peer `
                    $Connection $Session $Subject $Marker
            } $ledger $Type $Operation $Role $ProcessId $started $Peer $Connection $Session $Subject $markerHash
        }
        $runMarker = "run-attempt=$run;challenge=$challenge"
        $runMarkerHash = Get-TestSha256 ($utf8NoBom.GetBytes($runMarker))
        $null = & $validator {
            param($Ledger,$ProcessId,$Started,$Marker)
            Add-RuntimeLedgerEvent $Ledger 'RUN_STARTED' '' 'SUPERVISOR' $ProcessId `
                $Started '' '' '' ('0' * 64) $Marker
        } $ledger ([int]$ledger.supervisor_process_id) `
            ([string]$ledger.supervisor_process_started_at) $runMarkerHash
        Add 'PROCESS_STARTED' '' 'SOURCE_PROXY' 41001 'mcace-target' $sourceConnection $session ('0' * 64) 'source proxy'
        Add 'PROCESS_STARTED' '' 'TARGET_PROXY' 41002 'mcace-source' $targetConnection $session ('0' * 64) 'target proxy'
        Add 'PROCESS_STARTED' '' 'SOURCE_PAPER' 41003 'mcace-source' $sourceConnection $session ('0' * 64) 'source paper'
        Add 'PROCESS_STARTED' '' 'TARGET_PAPER' 41004 'mcace-target' $targetConnection $session ('0' * 64) 'target paper'
        Add 'PROCESS_STARTED' '' 'FABRIC_CLIENT' 41005 'mcace-source' $sourceConnection $session ('0' * 64) 'fabric client'
        Add 'GUI_PROMPT_RENDERED' '' 'FABRIC_CLIENT' 41005 'mcace-source' $sourceConnection $session $subject 'prompt rendered'
        $null = & $validator {
            param($Ledger,$ProcessId,$Started,$Connection,$Session,$Subject,$Marker)
            Add-RuntimeLedgerEvent $Ledger 'GUI_SIGNED_RECEIPT_VERIFIED' '' 'SUPERVISOR' `
                $ProcessId $Started 'mcace-source' $Connection $Session $Subject $Marker
        } $ledger ([int]$ledger.supervisor_process_id) ([string]$ledger.supervisor_process_started_at) `
            $sourceConnection $session $subject ([string]$attestationDoc.sha256)
        Add 'GUI_ACCEPTED' '' 'FABRIC_CLIENT' 41005 'mcace-source' $sourceConnection $session $subject 'accepted'
        Add 'SOURCE_CONNECTION_VERIFIED' '' 'FABRIC_CLIENT' 41005 'mcace-source' $sourceConnection $session $subject 'source verified'
        Add 'SOURCE_SECOND_EXPORT_REQUESTED' $sourceOperation 'SOURCE_PROXY' 41001 'mcace-target' $sourceConnection $session $subject 'source request'
        $sourceRejectOperation = if ($BadSourceCorrelation) { '8a' * 16 } else { $sourceOperation }
        Add 'SOURCE_SECOND_EXPORT_REJECTED' $sourceRejectOperation 'FABRIC_CLIENT' 41005 'mcace-target' $sourceConnection $session $subject 'source rejected'
        Add 'SOURCE_SECOND_EXPORT_NO_GRANT_CONFIRMED' $sourceOperation 'SOURCE_PROXY' 41001 'mcace-target' $sourceConnection $session $subject 'source no grant'
        Add 'TARGET_CONNECTION_VERIFIED' '' 'FABRIC_CLIENT' 41005 'mcace-target' $targetConnection $session $subject 'target verified'
        Add 'TARGET_INHERITED_EXPORT_REQUESTED' $targetOperation 'TARGET_PROXY' 41002 'mcace-source' $targetConnection $session $subject 'target request'
        Add 'TARGET_INHERITED_EXPORT_REJECTED' $targetOperation 'FABRIC_CLIENT' 41005 'mcace-source' $targetConnection $session $subject 'target rejected'
        Add 'TARGET_INHERITED_EXPORT_NO_GRANT_CONFIRMED' $targetOperation 'TARGET_PROXY' 41002 'mcace-source' $targetConnection $session $subject 'target no grant'
        $seal = & $validator { param($Ledger,$Challenge) Complete-RuntimeLedger $Ledger $Challenge } `
            $ledger $challenge
        return [pscustomobject]@{ run=$run; bytes=[IO.File]::ReadAllBytes($Path); seal=$seal }
    }
    $ledgerFixture = New-LedgerFixture (Join-Path $tempRoot 'runtime-events.jsonl') $false
    $ledgerValidated = & $validator {
        param($Bytes,$Commit,$Target,$Run,$Challenge)
        Assert-RuntimeLedgerBytes $Bytes $Commit $Target $Run $Challenge
    } $ledgerFixture.bytes $sourceCommit $targetVersion $ledgerFixture.run $challenge
    Assert-True ([int]$ledgerValidated.event_count -eq 18) 'valid ledger event count changed'
    Assert-True ([string]$ledgerValidated.gui_receipt_attestation_sha256 -ceq $attestationDoc.sha256) `
        'ledger does not bind the signed GUI receipt'
    $chainTampered = [byte[]]$ledgerFixture.bytes.Clone(); $chainTampered[100] = $chainTampered[100] -bxor 1
    Assert-Throws {
        $null = & $validator {
            param($Bytes,$Commit,$Target,$Run,$Challenge)
            Assert-RuntimeLedgerBytes $Bytes $Commit $Target $Run $Challenge
        } $chainTampered $sourceCommit $targetVersion $ledgerFixture.run $challenge
    } 'hash-chain tampering passed'
    $badLedgerFixture = New-LedgerFixture (Join-Path $tempRoot 'runtime-bad-correlation.jsonl') $true
    Assert-Throws {
        $null = & $validator {
            param($Bytes,$Commit,$Target,$Run,$Challenge)
            Assert-RuntimeLedgerBytes $Bytes $Commit $Target $Run $Challenge
        } $badLedgerFixture.bytes $sourceCommit $targetVersion $badLedgerFixture.run $challenge
    } 'exact negative attempt correlation is not enforced'

    # V4 helper takes both identities explicitly: capture/publisher pass A/A, while protected
    # readiness later validates a reconstructed R/A bundle without weakening either identity.
    $bundle = Join-Path $tempRoot 'release-bundle'
    [IO.Directory]::CreateDirectory($bundle) | Out-Null
    $jarNames = @('mcace-client-fabric-1.21.11.jar','mcace-client-fabric-26.1.2.jar',
        'mcace-client-fabric-26.2.jar','mcace-server-velocity.jar',
        'mcace-server-bungeecord.jar','mcace-server-paper.jar')
    $hashes = [ordered]@{}
    for ($index = 0; $index -lt $jarNames.Count; $index++) {
        $bytes = New-Object byte[] (2048 + $index)
        for ($offset = 0; $offset -lt $bytes.Length; $offset++) { $bytes[$offset] = [byte](($offset + $index) % 251) }
        [IO.File]::WriteAllBytes((Join-Path $bundle $jarNames[$index]), $bytes)
        $hashes[$jarNames[$index]] = Get-TestSha256 $bytes
    }
    $artifactCommit = '9' * 40
    $releaseCommit = '8' * 40
    $targetJar = 'mcace-client-fabric-26.2.jar'
    $manifest = @(
        'schema=MCACE_RELEASE_BUNDLE_V4','bundle_profile=RELEASE','release_identity=true',
        'deployable_count=6','bundle_entry_count=8','product_version=0.0.1',
        "source_commit=$releaseCommit","artifact_source_commit=$artifactCommit",
        "artifact.mcace_client_fabric_26_2.file=$targetJar",
        "artifact.mcace_client_fabric_26_2.sha256=$($hashes[$targetJar])",
        'artifact.mcace_client_fabric_26_2.minecraft_version=26.2',
        "artifact.mcace_client_fabric_26_2.client_build_id=fabric-26.2-$artifactCommit",
        'artifact.mcace_server_velocity.file=mcace-server-velocity.jar',
        "artifact.mcace_server_velocity.sha256=$($hashes['mcace-server-velocity.jar'])",
        'artifact.mcace_server_bungeecord.file=mcace-server-bungeecord.jar',
        "artifact.mcace_server_bungeecord.sha256=$($hashes['mcace-server-bungeecord.jar'])",
        'artifact.mcace_server_paper.file=mcace-server-paper.jar',
        "artifact.mcace_server_paper.sha256=$($hashes['mcace-server-paper.jar'])") -join "`n"
    [IO.File]::WriteAllText((Join-Path $bundle 'release-manifest.properties'), $manifest + "`n", $utf8NoBom)
    $sums = @($jarNames | ForEach-Object { "$($hashes[$_])  $_" }) -join "`n"
    [IO.File]::WriteAllText((Join-Path $bundle 'SHA256SUMS'), $sums + "`n", $utf8NoBom)
    $bundleBinding = & $validator {
        param($Root,$BundleCommit,$ArtifactCommit,$Target,$SourceProxy,$TargetProxy)
        Get-ReleaseBundleTargetBinding $Root $BundleCommit $ArtifactCommit $Target $SourceProxy $TargetProxy
    } $bundle $releaseCommit $artifactCommit '26.2' 'VELOCITY' 'BUNGEE'
    Assert-True ([string]$bundleBinding.fabric_jar_sha256 -ceq $hashes[$targetJar]) `
        'V4 bundle target JAR did not validate'
    Assert-True ([string]$bundleBinding.artifact_source_commit -ceq $artifactCommit) `
        'artifact_source_commit did not survive bundle validation'
    Assert-True ([string]$bundleBinding.paper_jar_sha256 -ceq $hashes['mcace-server-paper.jar']) `
        'Paper runtime JAR did not validate'
    Assert-True ([string]$bundleBinding.source_proxy_jar_sha256 -ceq $hashes['mcace-server-velocity.jar']) `
        'source proxy runtime JAR did not validate'
    Assert-True ([string]$bundleBinding.target_proxy_jar_sha256 -ceq $hashes['mcace-server-bungeecord.jar']) `
        'target proxy runtime JAR did not validate'
    foreach ($sameProxy in @('VELOCITY','BUNGEE')) {
        $sameProxyBinding = & $validator {
            param($Root,$BundleCommit,$ArtifactCommit,$Target,$SourceProxy,$TargetProxy)
            Get-ReleaseBundleTargetBinding $Root $BundleCommit $ArtifactCommit $Target $SourceProxy $TargetProxy
        } $bundle $releaseCommit $artifactCommit '26.2' $sameProxy $sameProxy
        Assert-True ([string]$sameProxyBinding.source_proxy_jar_sha256 -ceq
                [string]$sameProxyBinding.target_proxy_jar_sha256) `
            "same-family $sameProxy federation route did not bind the shared exact proxy JAR"
    }
    $manifestPath = Join-Path $bundle 'release-manifest.properties'
    $validManifest = [IO.File]::ReadAllText($manifestPath)
    [IO.File]::WriteAllText($manifestPath,
        $validManifest.Replace('MCACE_RELEASE_BUNDLE_V4','MCACE_RELEASE_BUNDLE_V3'), $utf8NoBom)
    Assert-Throws {
        $null = & $validator {
            param($Root,$BundleCommit,$ArtifactCommit,$Target,$SourceProxy,$TargetProxy)
            Get-ReleaseBundleTargetBinding $Root $BundleCommit $ArtifactCommit $Target $SourceProxy $TargetProxy
        } $bundle $releaseCommit $artifactCommit '26.2' 'VELOCITY' 'BUNGEE'
    } 'legacy V3 release bundle passed'
    [IO.File]::WriteAllText($manifestPath, $validManifest, $utf8NoBom)
    Assert-Throws {
        $null = & $validator {
            param($Root,$BundleCommit,$ArtifactCommit,$Target,$SourceProxy,$TargetProxy)
            Get-ReleaseBundleTargetBinding $Root $BundleCommit $ArtifactCommit $Target $SourceProxy $TargetProxy
        } $bundle $releaseCommit ('0' * 40) '26.2' 'VELOCITY' 'BUNGEE'
    } 'wrong artifact_source_commit passed'
    Assert-Throws {
        $null = & $validator {
            param($Root,$BundleCommit,$ArtifactCommit,$Target,$SourceProxy,$TargetProxy)
            Get-ReleaseBundleTargetBinding $Root $BundleCommit $ArtifactCommit $Target $SourceProxy $TargetProxy
        } $bundle ('0' * 40) $artifactCommit '26.2' 'VELOCITY' 'BUNGEE'
    } 'wrong bundle source_commit passed'
    $sumsPath = Join-Path $bundle 'SHA256SUMS'
    $validSums = [IO.File]::ReadAllText($sumsPath)
    [IO.File]::WriteAllText($sumsPath,
        $validSums.Replace([string]$hashes[$targetJar], ('0' * 64)), $utf8NoBom)
    Assert-Throws {
        $null = & $validator {
            param($Root,$BundleCommit,$ArtifactCommit,$Target,$SourceProxy,$TargetProxy)
            Get-ReleaseBundleTargetBinding $Root $BundleCommit $ArtifactCommit $Target $SourceProxy $TargetProxy
        } $bundle $releaseCommit $artifactCommit '26.2' 'VELOCITY' 'BUNGEE'
    } 'SHA256SUMS/JAR mismatch passed'
    [IO.File]::WriteAllText($sumsPath, $validSums, $utf8NoBom)

    # A second, independent RSA authority closes the run after the immutable report/binding and
    # append-only ledger exist. Both signer roots must be approved out of band and must not share
    # a key. Fixture provenance remains usable only inside this parser test.
    $postRunRsa = [Security.Cryptography.RSACryptoServiceProvider]::new(2048)
    $postRunRsa.PersistKeyInCsp = $false
    $postRunPublic = $postRunRsa.ExportParameters($false)
    $postRunTrustRoot = [ordered]@{
        schema='MCACE_FEDERATION_POSTRUN_TRUST_ROOT_V1'
        artifact_class='TEST_FEDERATION_POSTRUN_SIGNING_TRUST_ROOT_FIXTURE'
        key_id='fixture-postrun-signing-key-01'
        algorithm='RSA_PKCS1_SHA256'
        modulus_base64=[Convert]::ToBase64String($postRunPublic.Modulus)
        exponent_base64=[Convert]::ToBase64String($postRunPublic.Exponent)
        test_fixture=$true
    }
    $postRunTrustDoc = New-TestDocument `
        ($utf8NoBom.GetBytes(($postRunTrustRoot | ConvertTo-Json -Compress)))
    $validatedGuiRoot = & $validator {
        param($Root,$Sha) Assert-VisibleGuiTrustRoot $Root $Sha $Sha -AllowTestFixture
    } $trustDoc $trustDoc.sha256
    $validatedPostRunRoot = & $validator {
        param($Root,$Sha) Assert-PostRunSupervisorTrustRoot $Root $Sha $Sha -AllowTestFixture
    } $postRunTrustDoc $postRunTrustDoc.sha256
    $null = & $validator {
        param($Gui,$PostRun) Assert-DistinctFederationSignerRoots $Gui $PostRun
    } $validatedGuiRoot $validatedPostRunRoot

    # The production entrypoint obtains both approved pins from fixed process-environment names;
    # callers cannot smuggle either pin through the public parameter surface.
    $guiPinEnvironmentName = 'MCACE_RELEASE_APPROVED_FEDERATION_GUI_TRUST_ROOT_SHA256'
    $postRunPinEnvironmentName = 'MCACE_RELEASE_APPROVED_FEDERATION_POSTRUN_TRUST_ROOT_SHA256'
    $oldGuiPin = [Environment]::GetEnvironmentVariable($guiPinEnvironmentName, 'Process')
    $oldPostRunPin = [Environment]::GetEnvironmentVariable($postRunPinEnvironmentName, 'Process')
    try {
        [Environment]::SetEnvironmentVariable($guiPinEnvironmentName, $trustDoc.sha256, 'Process')
        [Environment]::SetEnvironmentVariable(
            $postRunPinEnvironmentName, $postRunTrustDoc.sha256, 'Process')
        $frozenGuiPin = & $validator {
            param($Name) Get-ApprovedReleaseSignerPin $Name 'GUI_TRUST_ROOT'
        } $guiPinEnvironmentName
        $frozenPostRunPin = & $validator {
            param($Name) Get-ApprovedReleaseSignerPin $Name 'POSTRUN_TRUST_ROOT'
        } $postRunPinEnvironmentName
        Assert-True ($frozenGuiPin -ceq $trustDoc.sha256) 'GUI approved pin was not read exactly'
        Assert-True ($frozenPostRunPin -ceq $postRunTrustDoc.sha256) `
            'post-run approved pin was not read exactly'
        [Environment]::SetEnvironmentVariable($postRunPinEnvironmentName, 'not-a-sha256', 'Process')
        Assert-Throws {
            $null = & $validator {
                param($Name) Get-ApprovedReleaseSignerPin $Name 'POSTRUN_TRUST_ROOT'
            } $postRunPinEnvironmentName
        } 'invalid frozen post-run pin passed'
    } finally {
        [Environment]::SetEnvironmentVariable($guiPinEnvironmentName, $oldGuiPin, 'Process')
        [Environment]::SetEnvironmentVariable($postRunPinEnvironmentName, $oldPostRunPin, 'Process')
    }

    # A post-run trust root reusing the GUI public key is well-formed in isolation but must fail the
    # two-authority separation contract.
    $equalKeyPostRunRoot = [ordered]@{
        schema='MCACE_FEDERATION_POSTRUN_TRUST_ROOT_V1'
        artifact_class='TEST_FEDERATION_POSTRUN_SIGNING_TRUST_ROOT_FIXTURE'
        key_id='fixture-postrun-equal-gui-key-01'
        algorithm='RSA_PKCS1_SHA256'
        modulus_base64=[Convert]::ToBase64String($public.Modulus)
        exponent_base64=[Convert]::ToBase64String($public.Exponent)
        test_fixture=$true
    }
    $equalKeyPostRunDoc = New-TestDocument `
        ($utf8NoBom.GetBytes(($equalKeyPostRunRoot | ConvertTo-Json -Compress)))
    $validatedEqualKeyPostRunRoot = & $validator {
        param($Root,$Sha) Assert-PostRunSupervisorTrustRoot $Root $Sha $Sha -AllowTestFixture
    } $equalKeyPostRunDoc $equalKeyPostRunDoc.sha256
    Assert-Throws {
        $null = & $validator {
            param($Gui,$PostRun) Assert-DistinctFederationSignerRoots $Gui $PostRun
        } $validatedGuiRoot $validatedEqualKeyPostRunRoot
    } 'GUI and post-run authorities reused the same RSA key'

    $ledgerDoc = New-TestDocument $ledgerFixture.bytes
    $generatedAt = [DateTimeOffset]::UtcNow.AddSeconds(-3).ToString('o')
    $report = [ordered]@{
        schema='MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V5'
        generated_at=$generatedAt
        source_proxy='VELOCITY'
        target_proxy='BUNGEE'
        fabric_target=$targetVersion
        operator_visible_gui_trust_root_sha256=[string]$trustDoc.sha256
        operator_visible_gui_attestation_json_sha256=[string]$attestationDoc.sha256
        operator_visible_gui_attestation_json_size_bytes=[long]$attestationDoc.size_bytes
        operator_visible_gui_screenshot_sha256=[string]$pngDoc.sha256
        operator_visible_gui_screenshot_size_bytes=[long]$pngDoc.size_bytes
        operator_visible_gui_screenshot_width=[int]$png.width
        operator_visible_gui_screenshot_height=[int]$png.height
        operator_visible_gui_screenshot_decoded_pixel_sha256=[string]$png.decoded_pixel_sha256
        runtime_ledger_sha256=[string]$ledgerDoc.sha256
        runtime_ledger_size_bytes=[long]$ledgerDoc.size_bytes
        runtime_ledger_event_count=[int]$ledgerValidated.event_count
        runtime_ledger_head_sha256=[string]$ledgerValidated.head_sha256
        runtime_ledger_supervisor_seal_sha256=[string]$ledgerValidated.supervisor_seal_sha256
        release_bundle_manifest_sha256=[string]$bundleBinding.manifest_sha256
        release_bundle_fabric_jar_sha256=[string]$bundleBinding.fabric_jar_sha256
    }
    $reportDoc = New-TestDocument ($utf8NoBom.GetBytes(($report | ConvertTo-Json -Compress)))
    $current = [ordered]@{ source_commit=$releaseCommit }
    $binding = [ordered]@{
        schema='MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V5'
        report_schema='MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V5'
        report_generated_at=$generatedAt
        report_sha256=[string]$reportDoc.sha256
        source_mode='EXECUTED_REAL_FABRIC_GUI'
        source_proxy='VELOCITY'
        target_proxy='BUNGEE'
        visible_gui_trust_root_sha256=[string]$trustDoc.sha256
        visible_gui_attestation_sha256=[string]$attestationDoc.sha256
        visible_gui_attestation_size_bytes=[long]$attestationDoc.size_bytes
        visible_gui_screenshot_sha256=[string]$pngDoc.sha256
        visible_gui_screenshot_size_bytes=[long]$pngDoc.size_bytes
        visible_gui_screenshot_width=[int]$png.width
        visible_gui_screenshot_height=[int]$png.height
        visible_gui_screenshot_decoded_pixel_sha256=[string]$png.decoded_pixel_sha256
        runtime_ledger_sha256=[string]$ledgerDoc.sha256
        runtime_ledger_size_bytes=[long]$ledgerDoc.size_bytes
        runtime_ledger_event_count=[int]$ledgerValidated.event_count
        runtime_ledger_head_sha256=[string]$ledgerValidated.head_sha256
        runtime_ledger_supervisor_seal_sha256=[string]$ledgerValidated.supervisor_seal_sha256
        release_bundle_manifest_sha256=[string]$bundleBinding.manifest_sha256
        release_bundle_fabric_jar_sha256=[string]$bundleBinding.fabric_jar_sha256
        passed=$true
        source_commit=$releaseCommit
    }
    $bindingDoc = New-TestDocument ($utf8NoBom.GetBytes(($binding | ConvertTo-Json -Compress)))
    $validatedBinding = & $validator {
        param($Raw,$ReportSha,$Report,$Current)
        Assert-BindingRaw $Raw $ReportSha $Report $Current
    } $bindingDoc.raw $reportDoc.sha256 ([pscustomobject]$report) $current
    Assert-True ([string]$validatedBinding.schema -ceq
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V5') 'valid V5 binding failed'

    $tamperedReport = Copy-JsonObject ([pscustomobject]$report)
    $tamperedReport.runtime_ledger_sha256 = 'd' * 64
    $tamperedReportDoc = New-TestDocument `
        ($utf8NoBom.GetBytes(($tamperedReport | ConvertTo-Json -Compress)))
    Assert-Throws {
        $null = & $validator {
            param($Raw,$ReportSha,$Report,$Current)
            Assert-BindingRaw $Raw $ReportSha $Report $Current
        } $bindingDoc.raw $tamperedReportDoc.sha256 $tamperedReport $current
    } 'report tampering passed immutable binding verification'
    $tamperedBinding = Copy-JsonObject ([pscustomobject]$binding)
    $tamperedBinding.runtime_ledger_sha256 = 'e' * 64
    Assert-Throws {
        $null = & $validator {
            param($Raw,$ReportSha,$Report,$Current)
            Assert-BindingRaw $Raw $ReportSha $Report $Current
        } ($tamperedBinding | ConvertTo-Json -Compress) $reportDoc.sha256 `
            ([pscustomobject]$report) $current
    } 'binding tampering passed report correlation'
    $legacyBinding = Copy-JsonObject ([pscustomobject]$binding)
    $legacyBinding.schema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V4'
    Assert-Throws {
        $null = & $validator {
            param($Raw,$ReportSha,$Report,$Current)
            Assert-BindingRaw $Raw $ReportSha $Report $Current
        } ($legacyBinding | ConvertTo-Json -Compress) $reportDoc.sha256 `
            ([pscustomobject]$report) $current
    } 'legacy V4 federation binding passed the V5 parser'

    $postRunOperation = 'ab' * 16
    $postRunChallenge = 'cd' * 32
    $postRunChallengeIssued = [DateTimeOffset]::UtcNow.AddSeconds(-2)
    $postRunSignedAt = [DateTimeOffset]::UtcNow.AddSeconds(-1)
    $postRunExpected = [ordered]@{
        release_source_commit=$releaseCommit
        artifact_source_commit=$artifactCommit
        product_version='0.0.1'
        fabric_target=$targetVersion
        source_proxy='VELOCITY'
        target_proxy='BUNGEE'
        release_bundle_manifest_sha256=[string]$bundleBinding.manifest_sha256
        release_bundle_fabric_jar_sha256=[string]$bundleBinding.fabric_jar_sha256
        release_bundle_paper_jar_sha256=[string]$bundleBinding.paper_jar_sha256
        release_bundle_source_proxy_jar_sha256=[string]$bundleBinding.source_proxy_jar_sha256
        release_bundle_target_proxy_jar_sha256=[string]$bundleBinding.target_proxy_jar_sha256
        run_attempt_id=[string]$ledgerFixture.run
        gui_challenge_nonce=$challenge
        postrun_operation_attempt_id=$postRunOperation
        postrun_challenge_nonce=$postRunChallenge
        postrun_challenge_issued_at=$postRunChallengeIssued.ToString('o')
        supervisor_process_incarnation_id=[string]$ledgerValidated.supervisor_process_incarnation_id
        source_proxy_process_incarnation_id=[string]$ledgerValidated.source_proxy_process_incarnation_id
        target_proxy_process_incarnation_id=[string]$ledgerValidated.target_proxy_process_incarnation_id
        source_paper_process_incarnation_id=[string]$ledgerValidated.source_paper_process_incarnation_id
        target_paper_process_incarnation_id=[string]$ledgerValidated.target_paper_process_incarnation_id
        fabric_client_process_incarnation_id=[string]$ledgerValidated.fabric_client_process_incarnation_id
        visible_gui_attestation_sha256=[string]$attestationDoc.sha256
        visible_gui_screenshot_sha256=[string]$pngDoc.sha256
        visible_gui_screenshot_decoded_pixel_sha256=[string]$png.decoded_pixel_sha256
        runtime_ledger_sha256=[string]$ledgerDoc.sha256
        runtime_ledger_size_bytes=[long]$ledgerDoc.size_bytes
        runtime_ledger_head_sha256=[string]$ledgerValidated.head_sha256
        runtime_ledger_supervisor_seal_sha256=[string]$ledgerValidated.supervisor_seal_sha256
        runtime_ledger_event_count=[int]$ledgerValidated.event_count
        report_sha256=[string]$reportDoc.sha256
        report_size_bytes=[long]$reportDoc.size_bytes
        binding_sha256=[string]$bindingDoc.sha256
        binding_size_bytes=[long]$bindingDoc.size_bytes
    }
    $postRunReceipt = [ordered]@{
        schema='MCACE_FABRIC_FEDERATION_POSTRUN_RECEIPT_V1'
        artifact_class='TEST_FEDERATION_POSTRUN_RECEIPT_FIXTURE'
        source_mode='TEST_SIGNED_PARSER_FIXTURE'
        signed_at=$postRunSignedAt.ToString('o')
    }
    foreach ($entry in $postRunExpected.GetEnumerator()) {
        $postRunReceipt[[string]$entry.Key] = $entry.Value
    }
    $postRunReceipt.signer_key_id='fixture-postrun-signing-key-01'
    $postRunReceipt.signer_trust_root_sha256=[string]$postRunTrustDoc.sha256
    $postRunReceipt.signature_algorithm='RSA_PKCS1_SHA256'
    $postRunReceipt.test_fixture=$true
    $postRunReceipt.signature_base64=''

    function New-SignedPostRunReceiptDocument([object]$Value, [object]$Signer) {
        $Value.signature_base64 = ''
        $payload = & $validator {
            param($Receipt) Get-PostRunReceiptSigningPayload $Receipt
        } $Value
        $Value.signature_base64 = [Convert]::ToBase64String($Signer.SignData($payload, 'SHA256'))
        return New-TestDocument ($utf8NoBom.GetBytes(($Value | ConvertTo-Json -Compress)))
    }

    $postRunReceiptDoc = New-SignedPostRunReceiptDocument ([pscustomobject]$postRunReceipt) $postRunRsa
    $validatedPostRunReceipt = & $validator {
        param($Evidence,$Root,$RootSha,$Expected,$Issued)
        Assert-PostRunReceipt $Evidence $Root $RootSha $RootSha $Expected $Issued `
            -AllowTestFixture
    } $postRunReceiptDoc $postRunTrustDoc $postRunTrustDoc.sha256 $postRunExpected `
        $postRunChallengeIssued
    Assert-True ([string]$validatedPostRunReceipt.value.signer_key_id -ceq
        'fixture-postrun-signing-key-01') 'valid independently signed post-run receipt failed'

    Assert-Throws {
        $null = & $validator {
            param($Root,$Sha) Assert-PostRunSupervisorTrustRoot $Root $Sha $Sha
        } $postRunTrustDoc $postRunTrustDoc.sha256
    } 'fixture post-run trust root passed the release path'
    $releaseLikePostRunRoot = Copy-JsonObject ([pscustomobject]$postRunTrustRoot)
    $releaseLikePostRunRoot.artifact_class = `
        'OUT_OF_BAND_PINNED_FEDERATION_POSTRUN_SIGNING_TRUST_ROOT'
    $releaseLikePostRunRoot.test_fixture = $false
    $releaseLikePostRunRootDoc = New-TestDocument `
        ($utf8NoBom.GetBytes(($releaseLikePostRunRoot | ConvertTo-Json -Compress)))
    $fixtureReceiptOnReleaseRoot = Copy-JsonObject ([pscustomobject]$postRunReceipt)
    $fixtureReceiptOnReleaseRoot.signer_trust_root_sha256 = $releaseLikePostRunRootDoc.sha256
    $fixtureReceiptOnReleaseRootDoc = New-SignedPostRunReceiptDocument `
        $fixtureReceiptOnReleaseRoot $postRunRsa
    Assert-Throws {
        $null = & $validator {
            param($Evidence,$Root,$RootSha,$Expected,$Issued)
            Assert-PostRunReceipt $Evidence $Root $RootSha $RootSha $Expected $Issued
        } $fixtureReceiptOnReleaseRootDoc $releaseLikePostRunRootDoc `
            $releaseLikePostRunRootDoc.sha256 $postRunExpected $postRunChallengeIssued
    } 'fixture post-run receipt passed a production-shaped release root'

    foreach ($mutation in @(
            [pscustomobject]@{ name='runtime_ledger_sha256'; value=('f' * 64); message='fake ledger hash' },
            [pscustomobject]@{ name='report_sha256'; value=('1' * 64); message='report hash mismatch' },
            [pscustomobject]@{ name='binding_sha256'; value=('2' * 64); message='binding hash mismatch' })) {
        $mutatedReceipt = Copy-JsonObject ([pscustomobject]$postRunReceipt)
        $mutatedReceipt.($mutation.name) = $mutation.value
        $mutatedReceiptDoc = New-SignedPostRunReceiptDocument $mutatedReceipt $postRunRsa
        Assert-Throws {
            $null = & $validator {
                param($Evidence,$Root,$RootSha,$Expected,$Issued)
                Assert-PostRunReceipt $Evidence $Root $RootSha $RootSha $Expected $Issued `
                    -AllowTestFixture
            } $mutatedReceiptDoc $postRunTrustDoc $postRunTrustDoc.sha256 `
                $postRunExpected $postRunChallengeIssued
        } "self-consistently re-signed post-run $($mutation.message) passed"
    }
    $receiptSignatureTamper = Copy-JsonObject $validatedPostRunReceipt.value
    $receiptSignatureBytes = [Convert]::FromBase64String(
        [string]$receiptSignatureTamper.signature_base64)
    $receiptSignatureBytes[0] = $receiptSignatureBytes[0] -bxor 1
    $receiptSignatureTamper.signature_base64 = [Convert]::ToBase64String($receiptSignatureBytes)
    $receiptSignatureTamperDoc = New-TestDocument `
        ($utf8NoBom.GetBytes(($receiptSignatureTamper | ConvertTo-Json -Compress)))
    Assert-Throws {
        $null = & $validator {
            param($Evidence,$Root,$RootSha,$Expected,$Issued)
            Assert-PostRunReceipt $Evidence $Root $RootSha $RootSha $Expected $Issued `
                -AllowTestFixture
        } $receiptSignatureTamperDoc $postRunTrustDoc $postRunTrustDoc.sha256 `
            $postRunExpected $postRunChallengeIssued
    } 'tampered post-run RSA signature passed'

    # A wholly self-consistent alternate root+receipt remains rejected when it is not the frozen
    # approved post-run signer pin.
    $unapprovedPostRunRsa = [Security.Cryptography.RSACryptoServiceProvider]::new(2048)
    $unapprovedPostRunRsa.PersistKeyInCsp = $false
    $unapprovedPublic = $unapprovedPostRunRsa.ExportParameters($false)
    $unapprovedRoot = [ordered]@{
        schema='MCACE_FEDERATION_POSTRUN_TRUST_ROOT_V1'
        artifact_class='TEST_FEDERATION_POSTRUN_SIGNING_TRUST_ROOT_FIXTURE'
        key_id='fixture-unapproved-postrun-key-01'
        algorithm='RSA_PKCS1_SHA256'
        modulus_base64=[Convert]::ToBase64String($unapprovedPublic.Modulus)
        exponent_base64=[Convert]::ToBase64String($unapprovedPublic.Exponent)
        test_fixture=$true
    }
    $unapprovedRootDoc = New-TestDocument `
        ($utf8NoBom.GetBytes(($unapprovedRoot | ConvertTo-Json -Compress)))
    $unapprovedReceipt = Copy-JsonObject ([pscustomobject]$postRunReceipt)
    $unapprovedReceipt.signer_key_id = 'fixture-unapproved-postrun-key-01'
    $unapprovedReceipt.signer_trust_root_sha256 = $unapprovedRootDoc.sha256
    $unapprovedReceiptDoc = New-SignedPostRunReceiptDocument `
        $unapprovedReceipt $unapprovedPostRunRsa
    Assert-Throws {
        $null = & $validator {
            param($Evidence,$Root,$ExpectedRoot,$ApprovedRoot,$Expected,$Issued)
            Assert-PostRunReceipt $Evidence $Root $ExpectedRoot $ApprovedRoot $Expected $Issued `
                -AllowTestFixture
        } $unapprovedReceiptDoc $unapprovedRootDoc $unapprovedRootDoc.sha256 `
            $postRunTrustDoc.sha256 $postRunExpected $postRunChallengeIssued
    } 'unapproved self-consistent post-run root and receipt passed the frozen pin'

    $commit = [ordered]@{
        schema='MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V5'
        report_schema='MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V5'
        binding_schema='MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V5'
        generated_at=$generatedAt
        report_sha256=[string]$reportDoc.sha256
        binding_sha256=[string]$bindingDoc.sha256
        visible_gui_attestation_sha256=[string]$attestationDoc.sha256
        visible_gui_screenshot_sha256=[string]$pngDoc.sha256
        runtime_ledger_sha256=[string]$ledgerDoc.sha256
        runtime_ledger_head_sha256=[string]$ledgerValidated.head_sha256
        runtime_ledger_supervisor_seal_sha256=[string]$ledgerValidated.supervisor_seal_sha256
        release_bundle_manifest_sha256=[string]$bundleBinding.manifest_sha256
        release_bundle_fabric_jar_sha256=[string]$bundleBinding.fabric_jar_sha256
        postrun_receipt_schema='MCACE_FABRIC_FEDERATION_POSTRUN_RECEIPT_V1'
        postrun_receipt_sha256=[string]$postRunReceiptDoc.sha256
        postrun_receipt_size_bytes=[long]$postRunReceiptDoc.size_bytes
        postrun_trust_root_sha256=[string]$postRunTrustDoc.sha256
        postrun_signer_key_id='fixture-postrun-signing-key-01'
        postrun_operation_attempt_id=$postRunOperation
        postrun_challenge_nonce=$postRunChallenge
        fabric_target=$targetVersion
        source_proxy='VELOCITY'
        target_proxy='BUNGEE'
        passed=$true
    }
    $commitRaw = $commit | ConvertTo-Json -Compress
    $validatedCommit = & $validator {
        param($Raw,$ReportSha,$BindingSha,$Report,$ReceiptEvidence,$Receipt)
        Assert-CommitRaw $Raw $ReportSha $BindingSha $Report $ReceiptEvidence $Receipt
    } $commitRaw $reportDoc.sha256 $bindingDoc.sha256 ([pscustomobject]$report) `
        $postRunReceiptDoc $validatedPostRunReceipt.value
    Assert-True ([string]$validatedCommit.schema -ceq
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V5') 'valid V5 commit failed'
    foreach ($commitMutation in @(
            [pscustomobject]@{ name='runtime_ledger_sha256'; value=('3' * 64); message='ledger' },
            [pscustomobject]@{ name='postrun_receipt_sha256'; value=('4' * 64); message='receipt' },
            [pscustomobject]@{ name='binding_sha256'; value=('5' * 64); message='binding' })) {
        $tamperedCommit = Copy-JsonObject ([pscustomobject]$commit)
        $tamperedCommit.($commitMutation.name) = $commitMutation.value
        Assert-Throws {
            $null = & $validator {
                param($Raw,$ReportSha,$BindingSha,$Report,$ReceiptEvidence,$Receipt)
                Assert-CommitRaw $Raw $ReportSha $BindingSha $Report $ReceiptEvidence $Receipt
            } ($tamperedCommit | ConvertTo-Json -Compress) $reportDoc.sha256 $bindingDoc.sha256 `
                ([pscustomobject]$report) $postRunReceiptDoc $validatedPostRunReceipt.value
        } "commit $($commitMutation.message) tampering passed"
    }
    $legacyCommit = Copy-JsonObject ([pscustomobject]$commit)
    $legacyCommit.schema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V4'
    Assert-Throws {
        $null = & $validator {
            param($Raw,$ReportSha,$BindingSha,$Report,$ReceiptEvidence,$Receipt)
            Assert-CommitRaw $Raw $ReportSha $BindingSha $Report $ReceiptEvidence $Receipt
        } ($legacyCommit | ConvertTo-Json -Compress) $reportDoc.sha256 $bindingDoc.sha256 `
            ([pscustomobject]$report) $postRunReceiptDoc $validatedPostRunReceipt.value
    } 'legacy V4 federation commit passed the V5 parser'

    # The final evidence directory is exact: the canonical GUI signing request is preserved next
    # to its signed receipt, and adding the post-run receipt produces the only accepted eight-file set.
    $evidenceSetDirectory = Join-Path $tempRoot 'exact-v5-evidence-set'
    [IO.Directory]::CreateDirectory($evidenceSetDirectory) | Out-Null
    $evidenceSetBytes = [ordered]@{
        'binding.json'=$bindingDoc.bytes
        'commit.json'=$utf8NoBom.GetBytes($commitRaw)
        'report.json'=$reportDoc.bytes
        'runtime-events.jsonl'=$ledgerDoc.bytes
        'visible-gui-attestation.json'=$attestationDoc.bytes
        'visible-gui-signing-request.json'=$requestDoc.bytes
        'visible-gui.png'=$pngDoc.bytes
    }
    foreach ($entry in $evidenceSetBytes.GetEnumerator()) {
        [IO.File]::WriteAllBytes(
            (Join-Path $evidenceSetDirectory ([string]$entry.Key)), [byte[]]$entry.Value)
    }
    Assert-Throws {
        $null = & $validator {
            param($Directory) Assert-ExactFederationEvidenceDirectory $Directory
        } $evidenceSetDirectory
    } 'eight-file evidence directory passed without post-run-receipt.json'
    [IO.File]::WriteAllBytes(
        (Join-Path $evidenceSetDirectory 'post-run-receipt.json'), $postRunReceiptDoc.bytes)
    $null = & $validator {
        param($Directory) Assert-ExactFederationEvidenceDirectory $Directory
    } $evidenceSetDirectory

    # Windows no-follow tests. Junction coverage is mandatory. Symlink privilege can be absent on
    # locked-down hosts; in that case the test emits an explicit coverage gap and never claims the
    # strict symlink PASS marker.
    $realDirectory = Join-Path $tempRoot 'real-directory'
    [IO.Directory]::CreateDirectory($realDirectory) | Out-Null
    [IO.File]::WriteAllText((Join-Path $realDirectory 'leaf.txt'), 'identity', $utf8NoBom)
    $junction = Join-Path $tempRoot 'junction-directory'
    $null = New-Item -ItemType Junction -Path $junction -Target $realDirectory -ErrorAction Stop
    Assert-Throws {
        $null = & $validator { param($Path) Assert-DirectLocalPath $Path -Directory } $junction
    } 'junction path passed direct-path validation'
    Assert-Throws {
        $null = & $validator { param($Path) Get-NoFollowFileIdentity $Path -Directory } $junction
    } 'junction path passed no-follow handle validation'
    $symlink = Join-Path $tempRoot 'symbolic-link-directory'
    try {
        $null = New-Item -ItemType SymbolicLink -Path $symlink -Target $realDirectory -ErrorAction Stop
        Assert-Throws {
            $null = & $validator { param($Path) Assert-DirectLocalPath $Path -Directory } $symlink
        } 'symbolic-link path passed direct-path validation'
        Assert-Throws {
            $null = & $validator { param($Path) Get-NoFollowFileIdentity $Path -Directory } $symlink
        } 'symbolic-link path passed no-follow handle validation'
        $symlinkCovered = $true
    } catch {
        Write-Output 'FABRIC_FEDERATION_GUI_V5_SYMLINK_COVERAGE_UNAVAILABLE|host privilege or policy denied symbolic-link creation'
    }
} finally {
    if ($null -ne $atomicExchangeEvidence) { $atomicExchangeEvidence.stream.Dispose() }
    if ($null -ne $unapprovedPostRunRsa) { $unapprovedPostRunRsa.Dispose() }
    if ($null -ne $postRunRsa) { $postRunRsa.Dispose() }
    if ($null -ne $rsa) { $rsa.Dispose() }
    if ($null -ne $validator) { Remove-Module $validator -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($symlinkCovered) {
    Write-Output 'FABRIC_FEDERATION_GUI_HANDOFF_STATIC_V5_STRICT_PASS'
} else {
    Write-Output 'FABRIC_FEDERATION_GUI_HANDOFF_STATIC_V5_PASS_WITH_SYMLINK_PERMISSION_GAP'
}
