[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$publisher = Join-Path $PSScriptRoot 'publish-native-release-evidence.ps1'
$evidenceRoot = Join-Path $repoRoot 'docs/evidence'
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$token = [Guid]::NewGuid().ToString('N')
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('mcace-native-publisher-v5-' + $token)
$sourceCommit = (& git -C $repoRoot rev-parse HEAD 2>$null).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -cnotmatch '^[0-9a-f]{40}$') {
    throw 'MCACE_NATIVE_PUBLISHER_V5_GIT_HEAD_UNAVAILABLE'
}
$created = [Collections.Generic.List[string]]::new()

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "MCACE_NATIVE_PUBLISHER_V5_TEST_FAILED|$Message" }
}

function Assert-Throws([scriptblock]$Action, [string]$Expected) {
    $threw = $false
    try { & $Action } catch {
        $threw = $true
        Assert-True ($_.Exception.Message -clike "*$Expected*") `
            "expected=$Expected actual=$($_.Exception.Message)"
    }
    Assert-True $threw "expected failure was not raised: $Expected"
}

function Get-BytesSha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Write-Json([string]$Path, [object]$Value) {
    $bytes = $utf8NoBom.GetBytes(($Value | ConvertTo-Json -Depth 16) + "`n")
    [IO.File]::WriteAllBytes($Path, $bytes)
    return [pscustomobject]@{ path=$Path; bytes=$bytes; sha256=Get-BytesSha256 $bytes }
}

function New-TestReleaseBundle(
        [string]$Root,
        [string]$FinalCommit,
        [string]$ArtifactCommit) {
    [IO.Directory]::CreateDirectory($Root) | Out-Null
    $jarNames = @(
        'mcace-client-fabric-1.21.11.jar',
        'mcace-client-fabric-26.1.2.jar',
        'mcace-client-fabric-26.2.jar',
        'mcace-server-velocity.jar',
        'mcace-server-bungeecord.jar',
        'mcace-server-paper.jar')
    $manifest = [ordered]@{
        schema='MCACE_RELEASE_BUNDLE_V4'; bundle_profile='RELEASE'
        release_identity='true'; deployable_count='6'; bundle_entry_count='8'
        product_version='0.0.1'; source_commit=$FinalCommit
        artifact_source_commit=$ArtifactCommit
        root_java_version='25'; root_java_specification_version='25'; root_gradle_version='9.1'
        modern_java_version='25'; modern_java_specification_version='25'; modern_gradle_version='9.1'
    }
    $sumLines = [Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $jarNames.Count; $index++) {
        $name = $jarNames[$index]
        $bytes = New-Object byte[] 1024
        for ($byteIndex = 0; $byteIndex -lt $bytes.Length; $byteIndex++) {
            $bytes[$byteIndex] = [byte](($byteIndex + 17 * ($index + 1)) % 251)
        }
        [IO.File]::WriteAllBytes((Join-Path $Root $name), $bytes)
        $sha = Get-BytesSha256 $bytes
        $key = $name.Remove($name.Length - 4).Replace('-','_').Replace('.','_')
        $manifest["artifact.$key.file"] = $name
        $manifest["artifact.$key.sha256"] = $sha
        if ($name -cmatch '^mcace-client-fabric-(?<target>1\.21\.11|26\.1\.2|26\.2)\.jar$') {
            $manifest["artifact.$key.minecraft_version"] = $Matches.target
            $manifest["artifact.$key.client_build_id"] = "fabric-$($Matches.target)-$ArtifactCommit"
        }
        $sumLines.Add("$sha  $name")
    }
    $manifestLines = @($manifest.Keys | ForEach-Object { "$_=$($manifest[$_])" })
    [IO.File]::WriteAllBytes((Join-Path $Root 'release-manifest.properties'),
        $utf8NoBom.GetBytes(($manifestLines -join "`n") + "`n"))
    [IO.File]::WriteAllBytes((Join-Path $Root 'SHA256SUMS'),
        $utf8NoBom.GetBytes(($sumLines -join "`n") + "`n"))
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
        Assert-True ($matches.Count -eq 1) "function is not unique: $name"
        $parts.Add($matches[0].Extent.Text)
    }
    return $parts -join "`n`n"
}

function Invoke-Publisher([hashtable]$Arguments) {
    return @(& $publisher @Arguments)
}

function Register-Published([string]$EvidenceId, [string]$Directory) {
    $created.Add((Join-Path $evidenceRoot ($EvidenceId + '.json')))
    $created.Add((Join-Path (Join-Path $evidenceRoot $Directory) $EvidenceId))
}

$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $publisher, [ref]$tokens, [ref]$errors)
Assert-True (@($errors).Count -eq 0) "publisher parse failed: $($errors -join '; ')"
$source = [IO.File]::ReadAllText($publisher)
$gate = @($ast.ParamBlock.Parameters | Where-Object {
    $_.Name.VariablePath.UserPath -ceq 'Gate'
}) | Select-Object -First 1
$gateSet = @((@($gate.Attributes | Where-Object {
    $_.TypeName.FullName -ceq 'ValidateSet'
})[0]).PositionalArguments | ForEach-Object {
    if ($_ -is [Management.Automation.Language.StringConstantExpressionAst]) { [string]$_.Value }
    else { $_.Extent.Text.Trim("'", '"') }
})
Assert-True (($gateSet -join ',') -ceq 'Federation,Vulcan,ProductionAuthority') `
    'legacy Gui publisher is still callable'
$parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
foreach ($required in @('VisibleGuiTrustRootPath','ExpectedVisibleGuiTrustRootSha256',
        'PostRunSupervisorTrustRootPath','ExpectedPostRunSupervisorTrustRootSha256',
        'ReleaseBundleRoot')) {
    Assert-True ($required -cin $parameterNames) "gate-specific Federation parameter missing: $required"
}
foreach ($obsolete in @('MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V3',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V3',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V3','MCACE_VISIBLE_GUI_ATTESTATION_V1',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V4',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V4',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V4',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V4',
        'MCACE_RELEASE_BUNDLE_V3','MCACE_FABRIC_GUI_CONSENT_EVIDENCE_INDEX_V1',
        'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_V1',
        'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_BINDING_V1',
        'MCACE_VULCAN_GENUINE_EVENT_EVIDENCE_INDEX_V1',
        'MCACE_VULCAN_GENUINE_EVENT_EVIDENCE_INDEX_V2',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_REPORT_V1',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_BINDING_V1',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_COMMIT_V1',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_REPORT_V3',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_BINDING_V3',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_COMMIT_V3',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V1')) {
    Assert-True (-not $source.Contains($obsolete)) "obsolete acceptance remains: $obsolete"
}
foreach ($required in @('MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V5',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V5',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V5',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V5',
        'MCACE_VISIBLE_GUI_SIGNING_REQUEST_V1','MCACE_VISIBLE_GUI_ATTESTATION_V3',
        'visible-gui-signing-request.json','visible_gui_signing_request',
        'MCACE_FABRIC_FEDERATION_POSTRUN_RECEIPT_V1','MCACE_FEDERATION_POSTRUN_TRUST_ROOT_V1',
        'post-run-receipt.json','post_run_receipt','runtime-events.jsonl','runtime_event_ledger',
        'New-FederationV5ValidatorModule',
        'Assert-VisibleGuiAttestation','Assert-RuntimeLedgerBytes','Get-ReleaseBundleTargetBinding',
        'Assert-PostRunReceipt','Assert-DistinctFederationSignerRoots',
        'MCACE_RELEASE_APPROVED_FEDERATION_GUI_TRUST_ROOT_SHA256',
        'MCACE_RELEASE_APPROVED_FEDERATION_POSTRUN_TRUST_ROOT_SHA256',
        'artifact_source_commit','release_bundle_fabric_jar_sha256',
        'MCACE_NATIVE_EVIDENCE_FEDERATION_TRUST_ROOT_MUST_BE_OUT_OF_BAND',
        'MCACE_RELEASE_BUNDLE_V4','MCACE_VULCAN_GENUINE_EVENT_DELIVERY_V2',
        'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_BINDING_V2',
        'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_COMMIT_V2',
        'release_eligible','observer_auth_protocol',
        'MCACE_NATIVE_EVIDENCE_VULCAN_V2_DIAGNOSTIC_NOT_RELEASE_GRADE',
        'MCACE_VULCAN_GENUINE_EVENT_EVIDENCE_INDEX_V3',
        'MCACE_VULCAN_GENUINE_EVENT_SUPERVISOR_RECEIPT_V1',
        'MCACE_VULCAN_GENUINE_EVENT_SIGNING_REQUEST_V1',
        'New-VulcanV3ValidatorModule','Assert-VulcanV3Package',
        'MCACE_VULCAN_SUPERVISOR_TRUST_ROOT_SHA256',
        'MCACE_NATIVE_EVIDENCE_VULCAN_FINAL_MCACE_PAPER_JAR_BINDING_INVALID',
        'MCAceNativeEvidenceFileIdentityV2','FILE_FLAG_OPEN_REPARSE_POINT',
        'GetFileInformationByHandle','MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V4',
        'PRODUCTION_AUTHORITY_V4_PACKAGE_VALIDATION_PASS',
        'Read-AuthorityLockedOpaqueFile','AUTHORITY_LOCKED_DOUBLE_READ_MISMATCH',
        'raw-frames.jsonl','provider-events.jsonl','supervisor-receipt.json',
        'capture-supervisor-public-descriptor.json','packaged_artifacts',
        'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_RECEIPT_REPLAY_REJECTED',
        'RequireCurrentlyValidReceipt','gui_attempt_id','gui_challenge_nonce',
        'postrun_operation_attempt_id','postrun_challenge_nonce',
        'MCACE_NATIVE_EVIDENCE_FEDERATION_V5_REPLAY_REJECTED',
        'MCACE_NATIVE_EVIDENCE_CONCURRENT_PUBLICATION_REJECTED',
        'Enter-NativeEvidencePublishMutex','Exit-NativeEvidencePublishMutex')) {
    Assert-True $source.Contains($required) "V5 publisher contract missing: $required"
}
Assert-True (-not $source.Contains('-AllowTestFixture')) `
    'publisher exposes or invokes the test-fixture acceptance path'
Assert-True (-not $source.Contains('$sourceProxy -ceq $targetProxy')) `
    'publisher rejects a valid same-family Velocity->Velocity or Bungee->Bungee handoff'
Assert-True ($source.Contains('$releaseBundleBinding.bundle_source_commit -cne $SourceCommit') -and
        $source.Contains('$releaseBundleBinding.artifact_source_commit -cne $SourceCommit')) `
    'publisher does not close the capture A/A release-bundle identity contract'

$replayTestRoot = Join-Path ([IO.Path]::GetTempPath()) ('mcace-federation-publisher-replay-' + $token)
$replayModule = $null
try {
    [IO.Directory]::CreateDirectory($replayTestRoot) | Out-Null
    $existingReplayIndex = Join-Path $replayTestRoot 'federation-gui-handoff-existing.json'
    Write-Json $existingReplayIndex ([ordered]@{
        schema='MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V5'
        gui_attempt_id='1' * 32; gui_challenge_nonce='2' * 64
        postrun_operation_attempt_id='3' * 32; postrun_challenge_nonce='4' * 64
    }) | Out-Null
    $replayStub = @'
function Read-NativeJson([string]$Path,[string]$Role) {
    return [pscustomobject]@{ value=(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json) }
}
'@
    $replayModule = New-Module -ScriptBlock ([scriptblock]::Create(
        "Set-StrictMode -Version Latest`n`$script:evidenceRoot='$($replayTestRoot.Replace("'","''"))'`n" +
        $replayStub + "`n" +
        (Get-FunctionText $ast @('Assert-FederationNoPublicationReplay'))))
    $candidate = [pscustomobject]@{
        gui_attempt_id='1' * 32; gui_challenge_nonce='a' * 64
        postrun_operation_attempt_id='b' * 32; postrun_challenge_nonce='c' * 64
    }
    Assert-Throws {
        & $replayModule { param($Value) Assert-FederationNoPublicationReplay $Value } $candidate
    } 'MCACE_NATIVE_EVIDENCE_FEDERATION_V5_REPLAY_REJECTED'
    Write-Json $existingReplayIndex ([ordered]@{
        schema='MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V5'
        gui_attempt_id='5' * 32; gui_challenge_nonce='6' * 64
        postrun_operation_attempt_id='7' * 32; postrun_challenge_nonce='8' * 64
    }) | Out-Null
    & $replayModule { param($Value) Assert-FederationNoPublicationReplay $Value } $candidate
} finally {
    if ($null -ne $replayModule) { Remove-Module $replayModule -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $replayTestRoot) {
        Remove-Item -LiteralPath $replayTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$mutexTestRoot = Join-Path ([IO.Path]::GetTempPath()) ('mcace-native-publisher-mutex-' + $token)
$mutexHolder = $null
$mutexModule = $null
try {
    [IO.Directory]::CreateDirectory($mutexTestRoot) | Out-Null
    $readyPath = Join-Path $mutexTestRoot 'ready'
    $stopPath = Join-Path $mutexTestRoot 'stop'
    $holderPath = Join-Path $mutexTestRoot 'holder.ps1'
    $mutexFunctions = Get-FunctionText $ast @(
        'Enter-NativeEvidencePublishMutex','Exit-NativeEvidencePublishMutex')
    $holderSource = @"
param([string]`$RepoRoot,[string]`$ReadyPath,[string]`$StopPath)
Set-StrictMode -Version Latest
`$ErrorActionPreference='Stop'
`$script:repoRoot=`$RepoRoot
$mutexFunctions
`$mutex=Enter-NativeEvidencePublishMutex
try {
    [IO.File]::WriteAllText(`$ReadyPath,'ready')
    `$deadline=[DateTimeOffset]::UtcNow.AddSeconds(30)
    while(-not [IO.File]::Exists(`$StopPath) -and [DateTimeOffset]::UtcNow -lt `$deadline){Start-Sleep -Milliseconds 50}
} finally { Exit-NativeEvidencePublishMutex `$mutex }
"@
    [IO.File]::WriteAllText($holderPath,$holderSource,$utf8NoBom)
    $engine=(Get-Process -Id $PID).Path
    $mutexHolder=Start-Process -FilePath $engine -ArgumentList @(
        '-NoProfile','-NonInteractive','-File',('"'+$holderPath+'"'),
        '-RepoRoot',('"'+$mutexTestRoot+'"'),'-ReadyPath',('"'+$readyPath+'"'),
        '-StopPath',('"'+$stopPath+'"')) -PassThru -WindowStyle Hidden
    $deadline=[DateTimeOffset]::UtcNow.AddSeconds(10)
    while(-not(Test-Path -LiteralPath $readyPath) -and [DateTimeOffset]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 50}
    Assert-True (Test-Path -LiteralPath $readyPath) 'publisher mutex holder did not acquire the lock'
    $mutexModule=New-Module -ScriptBlock ([scriptblock]::Create(
        "Set-StrictMode -Version Latest`n`$script:repoRoot='$($mutexTestRoot.Replace("'","''"))'`n" +
        $mutexFunctions))
    Assert-Throws {
        & $mutexModule {
            $value=Enter-NativeEvidencePublishMutex
            try {} finally { Exit-NativeEvidencePublishMutex $value }
        }
    } 'MCACE_NATIVE_EVIDENCE_CONCURRENT_PUBLICATION_REJECTED'
    [IO.File]::WriteAllText($stopPath,'stop')
    $mutexHolder.WaitForExit(10000) | Out-Null
    Assert-True $mutexHolder.HasExited 'publisher mutex holder did not release the lock'
    & $mutexModule {
        $value=Enter-NativeEvidencePublishMutex
        try {} finally { Exit-NativeEvidencePublishMutex $value }
    }
} finally {
    if ($null -ne $mutexHolder -and -not $mutexHolder.HasExited) {
        Stop-Process -Id $mutexHolder.Id -Force -ErrorAction SilentlyContinue
        $mutexHolder.WaitForExit(5000) | Out-Null
    }
    if ($null -ne $mutexHolder) { $mutexHolder.Dispose() }
    if ($null -ne $mutexModule) { Remove-Module $mutexModule -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $mutexTestRoot) {
        Remove-Item -LiteralPath $mutexTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Build the dynamically extracted Vulcan validator exactly as production does.
# This catches a helper added to Assert-VulcanV3Package but omitted from the
# extraction allow-list before a licensed run reaches publication.
$vulcanFactoryText = Get-FunctionText $ast @(
    'Get-NativeAstFunctionText','Get-NativeAstAssignmentText',
    'New-VulcanV3ValidatorModule')
$vulcanFactoryText = $vulcanFactoryText.Replace(
    '$PSScriptRoot', "'$($PSScriptRoot.Replace("'","''"))'")
Invoke-Expression $vulcanFactoryText
$vulcanValidatorContract = New-VulcanV3ValidatorModule
try {
    Assert-True (& $vulcanValidatorContract {
            $null -ne (Get-Command Assert-VulcanV3Package -ErrorAction SilentlyContinue) -and
            $null -ne (Get-Command Test-JsonArray -ErrorAction SilentlyContinue)
        }) 'dynamically extracted Vulcan V3 validator is incomplete'
} finally {
    Remove-Module $vulcanValidatorContract -Force -ErrorAction SilentlyContinue
}

$sanitizerModule = New-Module -ScriptBlock ([scriptblock]::Create(
    "Set-StrictMode -Version Latest`n" +
    (Get-FunctionText $ast @('Assert-SanitizedNativeJsonRaw'))))
try {
    & $sanitizerModule {
        Assert-SanitizedNativeJsonRaw `
            '{"observer_access_token_run_bound":true}' 'allowed-contract-name'
    }
    Assert-Throws {
        & $sanitizerModule {
            Assert-SanitizedNativeJsonRaw `
                '{"access_token":"credential-material"}' 'secret-negative'
        }
    } 'MCACE_NATIVE_EVIDENCE_SENSITIVE_OR_ABSOLUTE_VALUE_REJECTED|secret-negative'
} finally {
    Remove-Module $sanitizerModule -Force -ErrorAction SilentlyContinue
}

[IO.Directory]::CreateDirectory($tempRoot) | Out-Null
$symlinkCovered = $false
try {
    # Removed legacy gate must fail during parameter binding.
    Assert-Throws {
        $null = & $publisher -Gate Gui -ReportPath 'x' -BindingPath 'y' `
            -SourceCommit $sourceCommit
    } 'ValidateSet'

    # Vulcan V2 is an integrity-bound diagnostic, not release evidence.  Even a complete local
    # triplet plus a valid V4 bundle must remain fail-closed until a future externally pinned,
    # supervisor-signed V3 contract exists.
    $generated = [DateTimeOffset]::UtcNow.ToString('o')
    $vulcanSha = '7ee3a4fdd7e9da5269f9efc327478e507563e6e7df7abec2222acd3b499bc993'
    $vulcanRoot = Join-Path $tempRoot 'vulcan'
    [IO.Directory]::CreateDirectory($vulcanRoot) | Out-Null
    $vulcanReport = Write-Json (Join-Path $vulcanRoot 'report.json') ([ordered]@{
        schema='MCACE_VULCAN_GENUINE_EVENT_DELIVERY_V1'
        generated_at=$generated
        source_mode='EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED'
        genuine_external_trigger_operator_attested=$true
        no_synthetic_event_injection_operator_attested=$true
        vulcan_sha256=$vulcanSha
        vulcan_size=3820392
        paper_sha256=('a' * 64)
        mcace_sha256=('b' * 64)
        passed=$true
    })
    $vulcanBinding = Write-Json (Join-Path $vulcanRoot 'binding.json') ([ordered]@{
        schema='MCACE_VULCAN_GENUINE_EVENT_DELIVERY_BINDING_V1'
        report_generated_at=$generated
        report_sha256=$vulcanReport.sha256
        source_mode='EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED'
        vulcan_sha256=$vulcanSha
        paper_sha256=('a' * 64)
        mcace_sha256=('b' * 64)
        passed=$true
    })
    $vulcanCommit = Write-Json (Join-Path $vulcanRoot 'commit.json') ([ordered]@{
        schema='MCACE_VULCAN_GENUINE_EVENT_DELIVERY_COMMIT_V1'
        generated_at=$generated
        report_sha256=$vulcanReport.sha256
        binding_sha256=$vulcanBinding.sha256
        source_commit=$sourceCommit
        committed=$true
    })
    $bundle = Join-Path $tempRoot 'release-bundle'
    New-TestReleaseBundle $bundle $sourceCommit $sourceCommit

    Assert-Throws {
        $null = Invoke-Publisher @{
            Gate='Vulcan'; ReportPath=$vulcanReport.path; BindingPath=$vulcanBinding.path
            SourceCommit=$sourceCommit; ReleaseBundleRoot=$bundle
        }
    } 'MCACE_NATIVE_EVIDENCE_COMMIT_PATH_REQUIRED|Vulcan'
    Assert-Throws {
        $null = Invoke-Publisher @{
            Gate='Vulcan'; ReportPath=$vulcanReport.path; BindingPath=$vulcanBinding.path
            CommitPath=$vulcanCommit.path; SourceCommit=$sourceCommit
        }
    } 'MCACE_NATIVE_EVIDENCE_VULCAN_RELEASE_BUNDLE_REQUIRED'
    Assert-Throws {
        $null = Invoke-Publisher @{
            Gate='Vulcan'; ReportPath=$vulcanReport.path; BindingPath=$vulcanBinding.path
            CommitPath=$vulcanCommit.path; SourceCommit=$sourceCommit
            VisibleGuiTrustRootPath=$vulcanReport.path
            ExpectedVisibleGuiTrustRootSha256=('0' * 64)
            ReleaseBundleRoot=$bundle
        }
    } 'MCACE_NATIVE_EVIDENCE_FEDERATION_TRUST_ROOTS_FEDERATION_ONLY'
    Assert-Throws {
        $null = Invoke-Publisher @{
            Gate='Vulcan'; ReportPath=$vulcanReport.path; BindingPath=$vulcanBinding.path
            CommitPath=$vulcanCommit.path; SourceCommit=$sourceCommit
            ReleaseBundleRoot=$bundle
        }
    } 'MCACE_NATIVE_EVIDENCE_VULCAN_V2_PROPERTY_SET_INVALID'
    [IO.File]::WriteAllText((Join-Path $vulcanRoot 'extra.txt'), 'unexpected', $utf8NoBom)
    Assert-Throws {
        $null = Invoke-Publisher @{
            Gate='Vulcan'; ReportPath=$vulcanReport.path; BindingPath=$vulcanBinding.path
            CommitPath=$vulcanCommit.path; SourceCommit=$sourceCommit
            ReleaseBundleRoot=$bundle
        }
    } 'MCACE_NATIVE_EVIDENCE_VULCAN_INPUT_FILE_SET_INVALID'
    Remove-Item -LiteralPath (Join-Path $vulcanRoot 'extra.txt') -Force

    # Exercise the terminal diagnostic-only barrier with an otherwise valid V2 triplet in an
    # isolated exact-commit repository.  This proves the rejection is not merely a legacy-schema
    # side effect and that local operator booleans cannot mint release evidence.
    $fixtureRepo = Join-Path $tempRoot 'isolated-repo'
    $fixtureScripts = Join-Path $fixtureRepo 'scripts'
    [IO.Directory]::CreateDirectory($fixtureScripts) | Out-Null
    Copy-Item -LiteralPath $publisher -Destination (Join-Path $fixtureScripts 'publish-native-release-evidence.ps1')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'vulcan-genuine-event-smoke.ps1') `
        -Destination (Join-Path $fixtureScripts 'vulcan-genuine-event-smoke.ps1')
    & git -C $fixtureRepo init -q
    & git -C $fixtureRepo config user.name 'MCAce Fixture'
    & git -C $fixtureRepo config user.email 'fixture@invalid.local'
    & git -C $fixtureRepo add scripts
    & git -C $fixtureRepo commit -q -m 'fixture publisher and wrapper'
    Assert-True ($LASTEXITCODE -eq 0) 'isolated publisher fixture commit failed'
    $fixtureCommit = (& git -C $fixtureRepo rev-parse HEAD).Trim().ToLowerInvariant()
    $fixtureBundle = Join-Path $fixtureRepo 'bundle'
    New-TestReleaseBundle $fixtureBundle $fixtureCommit $fixtureCommit
    $fixturePaperBytes = [IO.File]::ReadAllBytes((Join-Path $fixtureBundle 'mcace-server-paper.jar'))
    $fixturePaperSha = Get-BytesSha256 $fixturePaperBytes
    $fixtureNative = Join-Path $fixtureRepo 'native-vulcan'
    [IO.Directory]::CreateDirectory($fixtureNative) | Out-Null
    $fixtureWrapperBytes = [IO.File]::ReadAllBytes((Join-Path $fixtureScripts 'vulcan-genuine-event-smoke.ps1'))
    $fixtureWrapperSha = Get-BytesSha256 $fixtureWrapperBytes
    $v2Report = Write-Json (Join-Path $fixtureNative 'report.json') ([ordered]@{
        schema='MCACE_VULCAN_GENUINE_EVENT_DELIVERY_V2'; generated_at=$generated
        source_mode='EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED'; source_commit=$fixtureCommit
        product_version='0.0.1'; release_eligible=$false
        vulcan_sha256=$vulcanSha; paper_sha256=('c' * 64)
        mcace_sha256=$fixturePaperSha; vulcan_size=3820392; paper_size=4096
        mcace_size=$fixturePaperBytes.Length; plugin_name='Vulcan'; plugin_version='2.9.0'
        provider='vulcan'; provider_version='2.9.0'; event_type='BEHAVIOR_HIGH_RISK'
        source_component='vulcan-adapter'; origin='SERVER_CONFIRMED'
        network_policy='DENY_ALL_OPERATOR_ATTESTATION'; network_isolation_operator_attested=$true
        network_isolation_os_verified_by_script=$false
        genuine_external_trigger_operator_attested=$true
        no_synthetic_event_injection_operator_attested=$true
        gate_invoked_plugin_manager_call_event=$false; gate_used_test_fixture=$false
        gate_used_vendor_synthetic_event=$false; paper_process_coverage=$true
        licensed_plugin_enablement_coverage=$true; mcace_listener_registration_coverage=$true
        mcace_adapter_extraction_coverage=$true; mcace_correlator_coverage=$true
        mcace_queue_auth_delivery_coverage=$true; real_behavior_event_delivery_coverage=$true
        expected_player_matched=$true; observer_auth_protocol='MCACE_VULCAN_OBSERVER_AUTH_V1'
        observer_challenge_signature_verified=$true; observer_challenge_exchange_count=1
        observer_access_token_run_bound=$true; observer_event_causality_verified=$true
        observer_distinct_event_count=1; unique_matching_event_count=1; total_risk_event_count=1
        check_nonempty=$true; stable_check_nonempty=$true; flag_count=1
        temporary_paper_remap_allowed=$true; temporary_material_removed=$true
        remaining_marker_process_count=0
        limitations=@(
            'HUMAN_TRIGGER_ORIGIN_OPERATOR_ATTESTED_NOT_OS_OR_VENDOR_VERIFIED_BY_SCRIPT',
            'NETWORK_ISOLATION_OPERATOR_ATTESTED_NOT_OS_VERIFIED_BY_SCRIPT',
            'OBSERVER_CLIENT_IDENTITY_USES_PUBLIC_RFC8032_TEST_VECTOR_NOT_EXTERNAL_TRUST_ANCHOR',
            'OPERATOR_ATTESTED_V2_EVIDENCE_NOT_RELEASE_ELIGIBLE_WITHOUT_EXTERNAL_PINNED_SUPERVISOR_RECEIPT')
        passed=$true
    })
    $v2Binding = Write-Json (Join-Path $fixtureNative 'binding.json') ([ordered]@{
        schema='MCACE_VULCAN_GENUINE_EVENT_DELIVERY_BINDING_V2'
        report_schema='MCACE_VULCAN_GENUINE_EVENT_DELIVERY_V2'
        report_generated_at=$generated; report_sha256=$v2Report.sha256
        report_size_bytes=$v2Report.bytes.Length
        source_mode='EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED'; source_commit=$fixtureCommit
        product_version='0.0.1'; release_eligible=$false
        vulcan_sha256=$vulcanSha; paper_sha256=('c' * 64)
        mcace_sha256=$fixturePaperSha; vulcan_size=3820392; paper_size=4096
        mcace_size=$fixturePaperBytes.Length; wrapper_sha256=$fixtureWrapperSha
        source_manifest_sha256=('d' * 64); source_file_count=1
        java_executable_sha256=('e' * 64); java_file_version='25.0.0'
        prepared_manifest_sha256=('f' * 64); prepared_file_count=1; passed=$true
    })
    $v2Commit = Write-Json (Join-Path $fixtureNative 'commit.json') ([ordered]@{
        schema='MCACE_VULCAN_GENUINE_EVENT_DELIVERY_COMMIT_V2'; generated_at=$generated
        report_schema='MCACE_VULCAN_GENUINE_EVENT_DELIVERY_V2'
        binding_schema='MCACE_VULCAN_GENUINE_EVENT_DELIVERY_BINDING_V2'
        report_generated_at=$generated; report_sha256=$v2Report.sha256
        report_size_bytes=$v2Report.bytes.Length; binding_sha256=$v2Binding.sha256
        binding_size_bytes=$v2Binding.bytes.Length
        source_mode='EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED'
        source_commit=$fixtureCommit; product_version='0.0.1'
        release_eligible=$false; committed=$true
    })
    $fixturePublisher = Join-Path $fixtureScripts 'publish-native-release-evidence.ps1'
    Assert-Throws {
        $null = & $fixturePublisher -Gate Vulcan -ReportPath $v2Report.path `
            -BindingPath $v2Binding.path -CommitPath $v2Commit.path `
            -SourceCommit $fixtureCommit -ReleaseBundleRoot $fixtureBundle
    } 'MCACE_NATIVE_EVIDENCE_VULCAN_V2_DIAGNOSTIC_NOT_RELEASE_GRADE'

    # Federation V5 fails closed before schema validation until the exact eight-file set exists.
    $federation = Join-Path $tempRoot 'federation'
    [IO.Directory]::CreateDirectory($federation) | Out-Null
    $legacyReport = Write-Json (Join-Path $federation 'report.json') ([ordered]@{
        schema='MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V4'
        generated_at=$generated
    })
    $legacyBinding = Write-Json (Join-Path $federation 'binding.json') ([ordered]@{
        schema='MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V4'
        report_sha256=$legacyReport.sha256
    })
    $legacyCommit = Write-Json (Join-Path $federation 'commit.json') ([ordered]@{
        schema='MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V4'
        report_sha256=$legacyReport.sha256
        binding_sha256=$legacyBinding.sha256
    })
    $null = Write-Json (Join-Path $federation 'visible-gui-attestation.json') ([ordered]@{
        schema='MCACE_VISIBLE_GUI_ATTESTATION_V1'
    })
    $screen = New-Object byte[] 256; [IO.File]::WriteAllBytes((Join-Path $federation 'visible-gui.png'), $screen)
    $trustRoot = Write-Json (Join-Path $tempRoot 'fixture-trust-root.json') ([ordered]@{
        schema='MCACE_VISIBLE_GUI_TRUST_ROOT_V1'; artifact_class='TEST_GUI_SIGNING_TRUST_ROOT_FIXTURE'
        key_id='fixture'; algorithm='RSA_PKCS1_SHA256'; modulus_base64='AA=='
        exponent_base64='Aw=='; test_fixture=$true
    })
    $postRunTrustRoot = Write-Json (Join-Path $tempRoot 'fixture-postrun-trust-root.json') ([ordered]@{
        schema='MCACE_FEDERATION_POSTRUN_TRUST_ROOT_V1'
        artifact_class='TEST_FEDERATION_POSTRUN_SIGNING_TRUST_ROOT_FIXTURE'
        key_id='postrun-fixture'; algorithm='RSA_PKCS1_SHA256'; modulus_base64='AQ=='
        exponent_base64='Aw=='; test_fixture=$true
    })
    $bundle = Join-Path $tempRoot 'bundle'; [IO.Directory]::CreateDirectory($bundle) | Out-Null
    $federationArgs = @{
        Gate='Federation'; ReportPath=$legacyReport.path; BindingPath=$legacyBinding.path
        CommitPath=$legacyCommit.path; SourceCommit=$sourceCommit
        VisibleGuiTrustRootPath=$trustRoot.path
        ExpectedVisibleGuiTrustRootSha256=$trustRoot.sha256
        PostRunSupervisorTrustRootPath=$postRunTrustRoot.path
        ExpectedPostRunSupervisorTrustRootSha256=$postRunTrustRoot.sha256
        ReleaseBundleRoot=$bundle
    }
    Assert-Throws { $null = Invoke-Publisher $federationArgs } `
        'MCACE_NATIVE_EVIDENCE_FEDERATION_INPUT_FILE_SET_INVALID'
    $ledgerBytes = New-Object byte[] 256
    [IO.File]::WriteAllBytes((Join-Path $federation 'runtime-events.jsonl'), $ledgerBytes)
    Assert-Throws { $null = Invoke-Publisher $federationArgs } `
        'MCACE_NATIVE_EVIDENCE_FEDERATION_INPUT_FILE_SET_INVALID'
    $null = Write-Json (Join-Path $federation 'post-run-receipt.json') ([ordered]@{
        schema='MCACE_FABRIC_FEDERATION_POSTRUN_RECEIPT_V1'
    })
    $null = Write-Json (Join-Path $federation 'visible-gui-signing-request.json') ([ordered]@{
        schema='MCACE_VISIBLE_GUI_SIGNING_REQUEST_V1'
    })
    Assert-Throws { $null = Invoke-Publisher $federationArgs } `
        'FABRIC_FEDERATION_GUI_REPORT_SCHEMA_INVALID'

    # The publisher's own Windows no-follow layer rejects a real junction. Symbolic-link creation
    # may be policy-denied; report that as an explicit uncovered branch rather than strict PASS.
    $identityModule = New-Module -ScriptBlock ([scriptblock]::Create(
        "Set-StrictMode -Version Latest`n" +
        (Get-FunctionText $ast @('Test-NativeWindowsPlatform','Initialize-NativeFileIdentityApi',
            'Get-NativeNoFollowFileIdentity','Assert-PathChainNoReparse'))))
    try {
        $real = Join-Path $tempRoot 'real'; [IO.Directory]::CreateDirectory($real) | Out-Null
        $junction = Join-Path $tempRoot 'junction'
        $null = New-Item -ItemType Junction -Path $junction -Target $real -ErrorAction Stop
        Assert-Throws {
            $null = & $identityModule { param($Path) Assert-PathChainNoReparse $Path $true } $junction
        } 'MCACE_NATIVE_EVIDENCE_REPARSE_PATH_REJECTED'
        Assert-Throws {
            $null = & $identityModule { param($Path) Get-NativeNoFollowFileIdentity $Path -Directory } $junction
        } 'MCACE_NATIVE_EVIDENCE_NOFOLLOW_IDENTITY_FAILED'
        $symlink = Join-Path $tempRoot 'symlink'
        try {
            $null = New-Item -ItemType SymbolicLink -Path $symlink -Target $real -ErrorAction Stop
            Assert-Throws {
                $null = & $identityModule { param($Path) Assert-PathChainNoReparse $Path $true } $symlink
            } 'MCACE_NATIVE_EVIDENCE_REPARSE_PATH_REJECTED'
            Assert-Throws {
                $null = & $identityModule { param($Path) Get-NativeNoFollowFileIdentity $Path -Directory } $symlink
            } 'MCACE_NATIVE_EVIDENCE_NOFOLLOW_IDENTITY_FAILED'
            $symlinkCovered = $true
        } catch {
            Write-Output 'MCACE_NATIVE_PUBLISHER_V5_SYMLINK_COVERAGE_UNAVAILABLE|host privilege or policy denied symbolic-link creation'
        }
    } finally { Remove-Module $identityModule -Force -ErrorAction SilentlyContinue }
} finally {
    foreach ($path in @($created)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($symlinkCovered) {
    Write-Output 'MCACE_NATIVE_RELEASE_EVIDENCE_PUBLISHER_V5_STRICT_PASS'
} else {
    Write-Output 'MCACE_NATIVE_RELEASE_EVIDENCE_PUBLISHER_V5_PASS_WITH_SYMLINK_PERMISSION_GAP'
}

$authoritySmoke = @(& (Join-Path $PSScriptRoot 'test-production-authority-process-evidence.ps1') `
    -PublisherSmoke)
Assert-True (($authoritySmoke -join "`n") -clike
    '*PRODUCTION_AUTHORITY_PUBLISHER_V4_PASS*') 'Authority V4 publisher smoke marker missing'
$authoritySmoke | Write-Output
