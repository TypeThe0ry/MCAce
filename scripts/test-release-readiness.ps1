[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scriptPath = Join-Path $PSScriptRoot 'release-readiness.ps1'
$workflowPath = Join-Path $repoRoot '.github/workflows/build.yml'
$engine = (Get-Process -Id $PID).Path
$utf8NoBom = New-Object Text.UTF8Encoding($false)
$ascii = [Text.Encoding]::ASCII
$source = [IO.File]::ReadAllText($scriptPath)
$workflowSource = [IO.File]::ReadAllText($workflowPath)
$symlinkCovered = $false

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "RELEASE_READINESS_V5_TEST_FAILED|$Message" }
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

function Get-Sha256Bytes([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-Sha256File([string]$Path) {
    return Get-Sha256Bytes ([IO.File]::ReadAllBytes($Path))
}

function Write-JsonNoBom([string]$Path, [object]$Value, [int]$Depth = 30) {
    $json = ($Value | ConvertTo-Json -Depth $Depth) + "`n"
    [IO.File]::WriteAllBytes($Path, $utf8NoBom.GetBytes($json))
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

function Get-Gate([object]$Report, [string]$Name) {
    $items = @($Report.gates | Where-Object { [string]$_.name -ceq $Name })
    Assert-True ($items.Count -eq 1) "gate missing or duplicated: $Name"
    return $items[0]
}

function Assert-Gate([object]$Report, [string]$Name, [bool]$Expected) {
    $gate = Get-Gate $Report $Name
    Assert-True ($gate.passed -is [bool] -and [bool]$gate.passed -eq $Expected) `
        "gate=$Name expected=$Expected actual=$($gate.passed) detail=$($gate.detail)"
}

function Invoke-Readiness([string]$Root, [switch]$Protected) {
    $reportPath = Join-Path $Root 'build/release-readiness-test/report.json'
    [IO.Directory]::CreateDirectory((Split-Path -Parent $reportPath)) | Out-Null
    Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue
    $environmentNames = @('CI','GITHUB_ACTIONS','GITHUB_SERVER_URL','GITHUB_REPOSITORY',
        'GITHUB_EVENT_NAME','GITHUB_REF','GITHUB_REF_PROTECTED','GITHUB_SHA',
        'GITHUB_WORKFLOW_SHA','GITHUB_WORKFLOW_REF','GITHUB_JOB','RUNNER_ENVIRONMENT',
        'RUNNER_OS','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_WORKSPACE',
        'MCACE_PROTECTED_RELEASE_CI','MCACE_PROTECTED_RELEASE_ENVIRONMENT',
        'MCACE_RELEASE_APPROVED_FEDERATION_GUI_TRUST_ROOT_SHA256',
        'MCACE_RELEASE_APPROVED_FEDERATION_POSTRUN_TRUST_ROOT_SHA256',
        'MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256',
        'MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256',
        'MCACE_RELEASE_AUTHORITY_OPENSSL_PATH',
        'MCACE_RELEASE_AUTHORITY_OPENSSL_SHA256')
    $saved = @{}
    foreach ($name in $environmentNames) { $saved[$name] = [Environment]::GetEnvironmentVariable($name) }
    try {
        if ($Protected) {
            $commit = (& git -C $Root rev-parse HEAD 2>$null).Trim().ToLowerInvariant()
            $values = @{
                CI='true'; GITHUB_ACTIONS='true'; GITHUB_SERVER_URL='https://github.com'
                GITHUB_REPOSITORY='TypeThe0ry/MCAce'; GITHUB_EVENT_NAME='push'
                GITHUB_REF='refs/heads/main'; GITHUB_REF_PROTECTED='true'; GITHUB_SHA=$commit
                GITHUB_WORKFLOW_SHA=$commit
                GITHUB_WORKFLOW_REF='TypeThe0ry/MCAce/.github/workflows/build.yml@refs/heads/main'
                GITHUB_JOB='build'; RUNNER_ENVIRONMENT='github-hosted'; RUNNER_OS='Linux'
                GITHUB_RUN_ID='100'; GITHUB_RUN_ATTEMPT='1'
                GITHUB_WORKSPACE=[IO.Path]::GetFullPath($Root); MCACE_PROTECTED_RELEASE_CI='true'
                MCACE_PROTECTED_RELEASE_ENVIRONMENT='release'
            }
            foreach ($name in $environmentNames) {
                [Environment]::SetEnvironmentVariable($name, [string]$values[$name])
            }
        } else {
            foreach ($name in $environmentNames) { [Environment]::SetEnvironmentVariable($name, $null) }
        }
        $output = @(& $engine -NoLogo -NoProfile -ExecutionPolicy Bypass `
            -File (Join-Path $Root 'scripts/release-readiness.ps1') `
            -ReportPath $reportPath 2>&1)
        $exitCode = $LASTEXITCODE
        Assert-True ($exitCode -eq 1) "readiness must fail closed; exit=$exitCode output=$($output -join ' ')"
        Assert-True (Test-Path -LiteralPath $reportPath -PathType Leaf) `
            "readiness report missing: $reportPath"
        return (Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json)
    } finally {
        foreach ($name in $environmentNames) {
            [Environment]::SetEnvironmentVariable($name, [string]$saved[$name])
        }
    }
}

function New-TestReleaseBundle(
        [string]$Root,
        [string]$FinalCommit,
        [string]$ArtifactCommit) {
    [IO.Directory]::CreateDirectory($Root) | Out-Null
    $jarNames = @('mcace-client-fabric-1.21.11.jar','mcace-client-fabric-26.1.2.jar',
        'mcace-client-fabric-26.2.jar','mcace-server-velocity.jar',
        'mcace-server-bungeecord.jar','mcace-server-paper.jar')
    $manifest = [ordered]@{
        schema='MCACE_RELEASE_BUNDLE_V4'; bundle_profile='RELEASE'; release_identity='true'
        deployable_count='6'; bundle_entry_count='8'; product_version='0.0.1'
        source_commit=$FinalCommit; artifact_source_commit=$ArtifactCommit
        root_java_version='25'; root_java_specification_version='25'; root_gradle_version='9.1'
        modern_java_version='25'; modern_java_specification_version='25'; modern_gradle_version='9.1'
    }
    $hashes = [ordered]@{}
    $sumLines = [Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $jarNames.Count; $index++) {
        $name = $jarNames[$index]
        $bytes = New-Object byte[] 2048
        for ($byteIndex = 0; $byteIndex -lt $bytes.Length; $byteIndex++) {
            $bytes[$byteIndex] = [byte](($byteIndex + 31 * ($index + 1)) % 251)
        }
        [IO.File]::WriteAllBytes((Join-Path $Root $name), $bytes)
        $sha = Get-Sha256Bytes $bytes
        $hashes[$name] = $sha
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
    return [pscustomobject]@{ jar_names=$jarNames; hashes=[pscustomobject]$hashes }
}

function Write-CompatibilityReport(
        [string]$Root,
        [string]$FinalCommit,
        [string]$ArtifactCommit,
        [object]$Bundle) {
    $path = Join-Path $Root 'build/compatibility-contract/report.json'
    [IO.Directory]::CreateDirectory((Split-Path -Parent $path)) | Out-Null
    $targets = @(
        [ordered]@{ minecraft_version='1.21.11'; protocol=774; java_major=21
            artifact_mode='FINAL_REMAP_JAR'; artifact='mcace-client-fabric-1.21.11.jar'
            sha256=[string]$Bundle.hashes.'mcace-client-fabric-1.21.11.jar'
            nested_jar_count=5; passed=$true },
        [ordered]@{ minecraft_version='26.1.2'; protocol=775; java_major=25
            artifact_mode='FINAL_NAMED_JAR'; artifact='mcace-client-fabric-26.1.2.jar'
            sha256=[string]$Bundle.hashes.'mcace-client-fabric-26.1.2.jar'
            nested_jar_count=1; passed=$true },
        [ordered]@{ minecraft_version='26.2'; protocol=776; java_major=25
            artifact_mode='FINAL_NAMED_JAR'; artifact='mcace-client-fabric-26.2.jar'
            sha256=[string]$Bundle.hashes.'mcace-client-fabric-26.2.jar'
            nested_jar_count=1; passed=$true })
    Write-JsonNoBom $path ([ordered]@{
        schema='MCACE_VERSION_COMPATIBILITY_CONTRACT_V2'
        generated_at=[DateTimeOffset]::UtcNow.ToString('o')
        source_commit=$FinalCommit; artifact_source_commit=$ArtifactCommit
        target_count=3; exact_bundle_entry_count=8
        unsupported_versions_are_fail_closed=$true
        unsupported_examples=@('1.21.1','1.21.10','26.1','26.3')
        targets=$targets; passed=$true
    }) 12
}

$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, [ref]$tokens, [ref]$parseErrors)
Assert-True (@($parseErrors).Count -eq 0) "readiness parse failed: $($parseErrors -join '; ')"

foreach ($required in @(
        'MCACE_RELEASE_READINESS_V2','server_matrix_exact_source',
        'fabric_gui_single_enablement_confirmation','fabric_federation_real_handoff',
        'vulcan_genuine_event','production_server_confirmed_authority',
        'protected_exact_release_bundle','clean_worktree','ConvertFrom-StrictJsonRaw',
        'Read-ReleaseLockedFileBytes','MCAceReleaseReadinessFileIdentityV3',
        'FILE_FLAG_OPEN_REPARSE_POINT','GetFileInformationByHandle',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V5',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V5',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V5',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V5',
        'MCACE_VISIBLE_GUI_SIGNING_REQUEST_V1','MCACE_VISIBLE_GUI_ATTESTATION_V3',
        'MCACE_VISIBLE_GUI_TRUST_ROOT_V1','visible-gui-signing-request.json',
        'visible_gui_signing_request','Assert-VisibleGuiSigningRequest',
        'MCACE_FABRIC_FEDERATION_POSTRUN_RECEIPT_V1',
        'MCACE_FEDERATION_POSTRUN_TRUST_ROOT_V1','post-run-receipt.json','post_run_receipt',
        'MCACE_RELEASE_APPROVED_FEDERATION_GUI_TRUST_ROOT_SHA256',
        'MCACE_RELEASE_APPROVED_FEDERATION_POSTRUN_TRUST_ROOT_SHA256',
        'Assert-PostRunReceipt','Assert-DistinctFederationSignerRoots',
        'MCACE_FABRIC_FEDERATION_RUNTIME_EVENT_V1','runtime-events.jsonl',
        'runtime_event_ledger','Assert-VisibleGuiAttestation','Assert-RuntimeLedgerBytes',
        'visible_gui_trust_root_sha256','release_bundle_fabric_jar_sha256',
        'docs/evidence/release-artifact-source.txt','MCACE_RELEASE_BUNDLE_V4',
        'MCACE_VERSION_COMPATIBILITY_CONTRACT_V2','artifact_source_commit',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V4',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V4',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_BINDING_V4',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_COMMIT_V4',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_MANIFEST_V1',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_SET_V1',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_CASE_RUNTIME_SET_V1',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_PROCESS_INCARNATION_V1',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_RELEASE_ARTIFACT_SET_V1',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_PRODUCT_JAR_SET_V1',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_SIGNING_REQUEST_V1',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_RECEIPT_V1',
        'MCACE_SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_V1',
        'MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256',
        'OUT_OF_BAND_PINNED_MATRIX_SUPERVISOR_TRUST_ROOT',
        'EXTERNALLY_SIGNED_MATRIX_SUPERVISOR_RECEIPT','RSA_PKCS1_SHA256',
        'Read-MatrixLockedFileBytes',
        'Read-MatrixSupervisorTrustRootEvidence','Test-MatrixRsaPkcs1Sha256Signature',
        'Assert-MatrixSupervisorReceipt','Assert-MatrixNoSupervisorReplay',
        'MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_SIGNATURE_INVALID',
        'MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_EXPIRED_OR_TIME_INVALID',
        'MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_REPLAY_REJECTED',
        'MCACE_RELEASE_MATRIX_SELF_SUPERVISOR_TRUST_ROOT_REJECTED',
        'MCACE_RELEASE_MATRIX_SUPERVISOR_PIN_NOT_APPROVED',
        'MCACE_RELEASE_MATRIX_V2_V3_NOT_RELEASE_ELIGIBLE',
        'MCACE_RELEASE_MATRIX_PROTECTED_BUNDLE_INVALID',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V4',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_REPORT_V4',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_BINDING_V4',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_COMMIT_V4',
        'MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_V1',
        'EXTERNAL_SUPERVISOR_SIGNED_RAW_REVALIDATED_PRODUCTION_AUTHORITY',
        'MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256',
        'MCACE_RELEASE_AUTHORITY_OPENSSL_PATH','MCACE_RELEASE_AUTHORITY_OPENSSL_SHA256',
        'Read-ProductionAuthorityLockedFileBytes','[IO.FileShare]::None',
        'Assert-ProductionAuthorityExactDirectory',
        'Assert-ProductionAuthorityNoSupervisorReplay',
        'PRODUCTION_AUTHORITY_V4_PACKAGE_VALIDATION_PASS',
        'production-authority-process-evidence.ps1',
        'MCACE_RELEASE_PRODUCTION_AUTHORITY_V1_V3_NOT_RELEASE_ELIGIBLE',
        'MCACE_RELEASE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_REPLAY_REJECTED',
        'MCACE_RELEASE_PRODUCTION_AUTHORITY_RAW_REVALIDATION_MARKER_MISSING',
        'MCACE_VULCAN_GENUINE_EVENT_EVIDENCE_INDEX_V2',
        'MCACE_RELEASE_VULCAN_V2_DIAGNOSTIC_NOT_RELEASE_GRADE',
        'MCACE_VULCAN_GENUINE_EVENT_EVIDENCE_INDEX_V3',
        'MCACE_VULCAN_GENUINE_EVENT_SUPERVISOR_RECEIPT_V1',
        'MCACE_VULCAN_GENUINE_EVENT_SIGNING_REQUEST_V1',
        'MCACE_VULCAN_SUPERVISOR_TRUST_ROOT_SHA256',
        'Assert-VulcanV3Package','MCACE_RELEASE_VULCAN_V3_REPLAY_REJECTED',
        'Assert-FederationNoEvidenceReplay','MCACE_RELEASE_FEDERATION_V5_REPLAY_REJECTED',
        'gui_attempt_id','gui_challenge_nonce','postrun_operation_attempt_id',
        'postrun_challenge_nonce')) {
    Assert-True ($source.IndexOf($required,[StringComparison]::Ordinal) -ge 0) `
        "required contract missing: $required"
}
foreach ($forbidden in @(
        'function Assert-GuiIndex','MCACE_FABRIC_GUI_CONSENT_EVIDENCE_INDEX_V1',
        'MCACE_FABRIC_GUI_EVIDENCE_BINDING_V6',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V3',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V3',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V3',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V4',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V4',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V4',
        'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V4',
        'MCACE_VISIBLE_GUI_ATTESTATION_V1','MCACE_RELEASE_BUNDLE_V3',
        'MCACE_VERSION_COMPATIBILITY_CONTRACT_V1',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V1',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V1',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_BINDING_V1',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_COMMIT_V1',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_REPORT_V1',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_BINDING_V1',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_COMMIT_V1',
        'EXECUTED_PRODUCTION_AUTHORITY',
        'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_V1',
        'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_BINDING_V1',
        'MCACE_VULCAN_GENUINE_EVENT_EVIDENCE_INDEX_V1',
        'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_V2',
        'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_BINDING_V2',
        'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_COMMIT_V2',
        'MCACE_RELEASE_VULCAN_EXTERNALLY_PINNED_SUPERVISOR_V3_REQUIRED')) {
    Assert-True ($source.IndexOf($forbidden,[StringComparison]::Ordinal) -lt 0) `
        "obsolete production acceptance remains: $forbidden"
}
$matrixFunction = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-MatrixIndex'
}, $true))
Assert-True ($matrixFunction.Count -eq 1) 'Assert-MatrixIndex is missing or duplicated'
$matrixText = $matrixFunction[0].Extent.Text
foreach ($matrixToken in @(
        'Get-ReleaseArtifactSourceCommit','Test-BuildReleaseBundle',
        'MCACE_RELEASE_BUNDLE_V4','matrix_product_jars','report_bytes','binding_bytes',
        'raw_manifest','raw_reports','ordered_raw_report_set_sha256','signing_request',
        'supervisor_receipt','case_runtime_commitment_sha256','process_identity_count',
        'release_bundle_artifact_set_sha256','matrix_product_jar_set_sha256',
        'independent_supervisor_signature_required',
        'Assert-MatrixSupervisorSigningRequest','Assert-MatrixSupervisorReceipt',
        'Assert-MatrixNoSupervisorReplay','MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V2',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V3',
        'MCACE_RELEASE_MATRIX_INDEX_CHANGED_OR_NONCANONICAL',
        'return [pscustomobject]')) {
    Assert-True ($matrixText.Contains($matrixToken)) `
        "Matrix V4 supervisor/protected-bundle/raw-evidence token missing: $matrixToken"
}
Assert-True (-not $matrixText.Contains('MCACE_RELEASE_MATRIX_INDEPENDENT_SUPERVISOR_SIGNATURE_REQUIRED')) `
    'Matrix V4 validator still terminates at the V3 unsigned diagnostic barrier'
Assert-True ($matrixText.Contains('$Index.source_commit $artifactSourceCommit') -and
        $matrixText.Contains('$Index.release_bundle.source_commit $artifactSourceCommit') -and
        $matrixText.Contains('Test-SourceProvenance $artifactSourceCommit $RequestedCommit')) `
    'Matrix V4 does not model capture commit A plus evidence-only release commit R'
Assert-True (-not $matrixText.Contains('$Index.source_commit $RequestedCommit') -and
        -not $matrixText.Contains('$Index.release_bundle.source_commit $RequestedCommit') -and
        -not $matrixText.Contains('$report.release_source_commit $RequestedCommit') -and
        -not $matrixText.Contains('$binding.release_source_commit $RequestedCommit') -and
        -not $matrixText.Contains('$commit.release_source_commit $RequestedCommit')) `
    'Matrix V4 reintroduced the impossible tracked-evidence source-commit fixed point'
Assert-True ($matrixText.Contains('$finalManifest.sha256 -cne [string]$manifestDocument.sha256') -and
        -not $matrixText.Contains('$finalManifest.sha256 -cne [string]$Index.release_bundle.manifest_sha256')) `
    'Matrix V4 does not keep current-manifest TOCTOU separate from the historical A manifest'

$matrixSetFunction = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-MatrixSetSha256'
}, $true))
Assert-True ($matrixSetFunction.Count -eq 1) 'Get-MatrixSetSha256 is missing or duplicated'
$matrixSetText = $matrixSetFunction[0].Extent.Text
Assert-True ($matrixSetText.Contains('ConvertTo-Json -Depth 30 -Compress') -and
        $matrixSetText.Contains('Get-BytesSha256') -and
        -not $matrixSetText.Contains('return Get-CompactObjectSha256')) `
    'Matrix set commitments must use the shared no-trailing-newline encoding'

$releaseReaderFunction = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Read-ReleaseLockedFileBytes'
}, $true))
Assert-True ($releaseReaderFunction.Count -eq 1) 'Read-ReleaseLockedFileBytes is missing or duplicated'
Assert-True ($releaseReaderFunction[0].Extent.Text.Contains('identity=$before')) `
    'release locked-file reads must retain the initial identity for final TOCTOU comparison'

$federationFunction = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-FederationIndex'
}, $true))
Assert-True ($federationFunction.Count -eq 1) `
    'Assert-FederationIndex is missing or duplicated'
$federationText = $federationFunction[0].Extent.Text
Assert-True ($federationText.Contains('$Index.release_bundle_source_commit') -and
        $federationText.Contains('$Index.artifact_source_commit') -and
        $federationText.Contains('Test-SourceProvenance $Index.source_commit $RequestedCommit') -and
        $federationText.Contains('Test-SourceProvenance $Index.artifact_source_commit $RequestedCommit') -and
        $federationText.Contains('$Index.release_bundle_source_commit -cne $RequestedCommit') -and
        $federationText.Contains('Test-StringEqual $Index.artifact_source_commit $artifactSourceCommit') -and
        $federationText.Contains('$evidenceReleaseBinding')) `
    'Federation V5 capture-A/current-R release binding is incomplete'
Assert-True (-not $federationText.Contains('$Index.source_commit $artifactSourceCommit') -and
        -not $federationText.Contains('$Index.release_bundle_source_commit $artifactSourceCommit') -and
        -not $federationText.Contains('$Index.release_bundle_manifest_sha256 -cne' +
            "`n                    [string]`$releaseBinding.manifest_sha256")) `
    'Federation V5 reintroduced the tracked manifest/source fixed point'
Assert-True (-not $federationText.Contains(
        '$Index.source_proxy -ceq [string]$Index.target_proxy')) `
    'Federation V5 readiness rejects a valid same-family proxy handoff'
Assert-True ($federationText.Contains(
        'Get-ReleaseBundleTargetBinding $Root $BundleCommit $ArtifactCommit') -and
        $federationText.Contains('$RequestedCommit $artifactSourceCommit $target')) `
    'Federation V5 readiness does not validate the current R/A release bundle identities explicitly'
Assert-True ($federationText.Contains('Assert-FederationNoEvidenceReplay') -and
        $federationText.Contains('gui_attempt_id') -and
        $federationText.Contains('postrun_challenge_nonce')) `
    'Federation V5 readiness does not enforce signed GUI/post-run evidence single-use'

$federationScalarFunction = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-FederationIndexScalarFields'
}, $true))
Assert-True ($federationScalarFunction.Count -eq 1) `
    'Federation V5 scalar type validator is missing or duplicated'
$federationScalarModule = New-Module -ScriptBlock ([scriptblock]::Create(
    "Set-StrictMode -Version Latest`n" +
    (Get-FunctionText $ast @('Test-NonEmptyJsonString','Assert-FederationIndexScalarFields'))))
try {
    $scalarFields = [pscustomobject]@{
        fabric_target='26.2';source_proxy='VELOCITY';target_proxy='VELOCITY'
        gui_attempt_id='1' * 32;gui_challenge_nonce='2' * 64
        postrun_operation_attempt_id='3' * 32;postrun_challenge_nonce='4' * 64
        release_bundle_fabric_jar_file='mcace-client-fabric-26.2.jar'
    }
    & $federationScalarModule {
        param($Value) Assert-FederationIndexScalarFields $Value
    } $scalarFields
    $arrayTyped = $scalarFields.PSObject.Copy()
    $arrayTyped.gui_attempt_id = [object[]]@('1' * 32)
    Assert-Throws {
        & $federationScalarModule {
            param($Value) Assert-FederationIndexScalarFields $Value
        } $arrayTyped
    } 'MCACE_RELEASE_FEDERATION_INDEX_STRING_TYPE_INVALID|gui_attempt_id'
} finally {
    Remove-Module $federationScalarModule -Force -ErrorAction SilentlyContinue
}

$federationReplayRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('mcace-readiness-federation-replay-' + [Guid]::NewGuid().ToString('N'))
$federationReplayModule = $null
try {
    $federationReplayEvidence = Join-Path $federationReplayRoot 'docs/evidence'
    [IO.Directory]::CreateDirectory($federationReplayEvidence) | Out-Null
    $currentFederationRelative = 'docs/evidence/federation-gui-handoff-current.json'
    $otherFederationPath = Join-Path $federationReplayEvidence `
        'federation-gui-handoff-other.json'
    $candidate = [pscustomobject]@{
        gui_attempt_id='1' * 32; gui_challenge_nonce='2' * 64
        postrun_operation_attempt_id='3' * 32; postrun_challenge_nonce='4' * 64
    }
    Write-JsonNoBom (Join-Path $federationReplayRoot $currentFederationRelative) `
        ([ordered]@{schema='MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V5'
            gui_attempt_id=$candidate.gui_attempt_id;gui_challenge_nonce=$candidate.gui_challenge_nonce
            postrun_operation_attempt_id=$candidate.postrun_operation_attempt_id
            postrun_challenge_nonce=$candidate.postrun_challenge_nonce})
    Write-JsonNoBom $otherFederationPath `
        ([ordered]@{schema='MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V5'
            gui_attempt_id=$candidate.gui_attempt_id;gui_challenge_nonce='a' * 64
            postrun_operation_attempt_id='b' * 32;postrun_challenge_nonce='c' * 64})
    $federationReplayStub = @'
function Read-StrictRepoJson([string]$Relative,[string]$Prefix,[string]$ExpectedLeaf='') {
    $absolute = Join-Path $script:repoRoot $Relative
    return [pscustomobject]@{ value=(Get-Content -LiteralPath $absolute -Raw | ConvertFrom-Json) }
}
'@
    $federationReplayModule = New-Module -ScriptBlock ([scriptblock]::Create(
        "Set-StrictMode -Version Latest`n`$script:repoRoot='$($federationReplayRoot.Replace("'","''"))'`n" +
        "`$script:evidenceRootRelative='docs/evidence'`n" + $federationReplayStub + "`n" +
        (Get-FunctionText $ast @('Assert-FederationNoEvidenceReplay'))))
    Assert-Throws {
        & $federationReplayModule {
            param($Value,$Current) Assert-FederationNoEvidenceReplay $Value $Current
        } $candidate $currentFederationRelative
    } 'MCACE_RELEASE_FEDERATION_V5_REPLAY_REJECTED'
    Write-JsonNoBom $otherFederationPath `
        ([ordered]@{schema='MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V5'
            gui_attempt_id='5' * 32;gui_challenge_nonce='6' * 64
            postrun_operation_attempt_id='7' * 32;postrun_challenge_nonce='8' * 64})
    & $federationReplayModule {
        param($Value,$Current) Assert-FederationNoEvidenceReplay $Value $Current
    } $candidate $currentFederationRelative
} finally {
    if ($null -ne $federationReplayModule) {
        Remove-Module $federationReplayModule -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $federationReplayRoot) {
        Remove-Item -LiteralPath $federationReplayRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$authorityFunction = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-ProductionAuthorityIndex'
}, $true))
Assert-True ($authorityFunction.Count -eq 1) `
    'Assert-ProductionAuthorityIndex is missing or duplicated'
$authorityText = $authorityFunction[0].Extent.Text
foreach ($authorityToken in @(
        'MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V4',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_REPORT_V4',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_BINDING_V4',
        'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_COMMIT_V4',
        'artifact_manifest','raw_capture_manifest','raw_frames','provider_events',
        'paper_events','proxy_events','issuance_journal','process_ledger',
        'capture_supervisor_public_descriptor','supervisor_receipt','packaged_artifacts',
        'MCACE_RELEASE_BUNDLE_V4','paper_jar','velocity_jar','bungeecord_jar',
        'MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256',
        'MCACE_RELEASE_AUTHORITY_OPENSSL_PATH','MCACE_RELEASE_AUTHORITY_OPENSSL_SHA256',
        'PRODUCTION_AUTHORITY_V4_PACKAGE_VALIDATION_PASS',
        'Assert-ProductionAuthorityNoSupervisorReplay',
        'MCACE_RELEASE_PRODUCTION_AUTHORITY_V1_V3_NOT_RELEASE_ELIGIBLE',
        'return [pscustomobject]')) {
    Assert-True ($authorityText.Contains($authorityToken)) `
        "Authority V4 raw/pin/bundle validator token missing: $authorityToken"
}
Assert-True (-not $authorityText.Contains('real_process_expected_case_count') -and
        -not $authorityText.Contains('OperatorAttests') -and
        -not $authorityText.Contains('TrustedSupervisorKeySha256')) `
    'Authority readiness still accepts a legacy narrative/caller-boolean promotion surface'
Assert-True ($authorityText.Contains('$Index.release_bundle.source_commit') -and
        $authorityText.Contains('$artifactSourceCommit') -and
        $authorityText.Contains('Test-SourceProvenance $artifactSourceCommit $RequestedCommit') -and
        -not $authorityText.Contains('-RequireCurrentlyValidReceipt')) `
    'Authority V4 A/R provenance or immutable receipt revalidation contract is incomplete'
Assert-True (-not $authorityText.Contains('$Index.release_bundle.source_commit $RequestedCommit') -and
        -not $authorityText.Contains('MCACE_RELEASE_PRODUCTION_AUTHORITY_RELEASE_MANIFEST_MISMATCH')) `
    'Authority V4 reintroduced the tracked manifest/source fixed point'

$authorityWindowFunction = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-ProductionAuthorityHistoricalReceiptWindow'
}, $true))
Assert-True ($authorityWindowFunction.Count -eq 1) `
    'Authority historical receipt-window validator is missing or duplicated'
Assert-True (-not $authorityWindowFunction[0].Extent.Text.Contains('UtcNow')) `
    'Authority historical receipt-window validator reintroduced current-wall-clock expiry'
$authorityWindowModule = New-Module -ScriptBlock ([scriptblock]::Create(
    "Set-StrictMode -Version Latest`n" + $authorityWindowFunction[0].Extent.Text))
try {
    # The exchange expired before this test ran, but the immutable index was committed
    # inside the signed acceptance window and must remain historically valid.
    & $authorityWindowModule {
        Assert-ProductionAuthorityHistoricalReceiptWindow `
            ([DateTimeOffset]::UtcNow.AddMinutes(-11)) `
            ([DateTimeOffset]::UtcNow.AddMinutes(-12)) `
            ([DateTimeOffset]::UtcNow.AddMinutes(-10))
    }
    Assert-Throws {
        & $authorityWindowModule {
            Assert-ProductionAuthorityHistoricalReceiptWindow `
                ([DateTimeOffset]::UtcNow.AddMinutes(-9)) `
                ([DateTimeOffset]::UtcNow.AddMinutes(-12)) `
                ([DateTimeOffset]::UtcNow.AddMinutes(-10))
        }
    } 'MCACE_RELEASE_PRODUCTION_AUTHORITY_INDEX_RECEIPT_WINDOW_INVALID'
} finally {
    Remove-Module $authorityWindowModule -Force -ErrorAction SilentlyContinue
}

$syntheticModule = New-Module -ScriptBlock ([scriptblock]::Create(
    "Set-StrictMode -Version Latest`n" +
    (Get-FunctionText $ast @('Assert-MatrixNoSyntheticMarkers'))))
try {
    & $syntheticModule {
        param($Value) Assert-MatrixNoSyntheticMarkers $Value 'production-receipt'
    } ([pscustomobject]@{ test_fixture=$false; artifact_class='EXTERNALLY_SIGNED_MATRIX_SUPERVISOR_RECEIPT' })
    Assert-Throws {
        & $syntheticModule {
            param($Value) Assert-MatrixNoSyntheticMarkers $Value 'fixture-receipt'
        } ([pscustomobject]@{ test_fixture=$true })
    } 'MCACE_RELEASE_MATRIX_SYNTHETIC_EVIDENCE_REJECTED'
} finally { Remove-Module $syntheticModule -Force -ErrorAction SilentlyContinue }

# Exercise the independent Matrix V4 supervisor verifier itself rather than relying on
# source-token checks.  The same fixture runs under PowerShell 7 and Windows PowerShell 5.1.
$receiptPropertyAssignment = @'
$matrixSupervisorReceiptPropertyNames = @(
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
'@
$receiptModule = New-Module -ScriptBlock ([scriptblock]::Create(
    "Set-StrictMode -Version Latest`n" + $receiptPropertyAssignment + "`n" +
    (Get-FunctionText $ast @('Test-JsonInteger','Test-StringEqual','Get-ExactPropertyNames',
        'Test-ExactProperties',
        'ConvertTo-EvidenceTime','Get-MatrixSupervisorReceiptSigningPayload',
        'Test-MatrixRsaPkcs1Sha256Signature','Assert-MatrixSupervisorReceipt'))))
$rsa = [Security.Cryptography.RSACryptoServiceProvider]::new(2048)
try {
    $rsa.PersistKeyInCsp = $false
    $public = $rsa.ExportParameters($false)
    $rootSha = '4' * 64
    $keyId = 'matrix-supervisor-production-1'
    $issued = [DateTimeOffset]::UtcNow.AddMinutes(-1)
    $expires = $issued.AddMinutes(15)
    $request = [pscustomobject][ordered]@{
        release_source_commit='1' * 40; artifact_source_commit='2' * 40
        product_version='0.0.1'; operation_attempt_id='3' * 32
        challenge_nonce='5' * 64; challenge_issued_at=$issued.ToString('o')
        report_sha256='6' * 64; report_size_bytes=1000L
        binding_sha256='7' * 64; binding_size_bytes=900L
        raw_manifest_sha256='8' * 64; raw_manifest_size_bytes=800L
        ordered_raw_report_set_sha256='9' * 64
        case_runtime_commitment_sha256='a' * 64; case_count=12
        process_identity_count=24; release_bundle_schema='MCACE_RELEASE_BUNDLE_V4'
        release_bundle_manifest_sha256='b' * 64; release_bundle_manifest_size_bytes=700L
        release_bundle_sha256s_sha256='c' * 64; release_bundle_sha256s_size_bytes=600L
        release_bundle_artifact_set_sha256='d' * 64; release_bundle_artifact_count=6
        matrix_product_jar_set_sha256='e' * 64; matrix_product_jar_count=3
    }
    $receipt = [pscustomobject][ordered]@{
        schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_RECEIPT_V1'
        artifact_class='EXTERNALLY_SIGNED_MATRIX_SUPERVISOR_RECEIPT'
        source_mode='EXTERNAL_MATRIX_SUPERVISOR'; signed_at=$issued.AddSeconds(1).ToString('o')
        expires_at=$expires.ToString('o'); release_source_commit=$request.release_source_commit
        artifact_source_commit=$request.artifact_source_commit; product_version='0.0.1'
        operation_attempt_id=$request.operation_attempt_id; challenge_nonce=$request.challenge_nonce
        challenge_issued_at=$request.challenge_issued_at; report_sha256=$request.report_sha256
        report_size_bytes=1000L; binding_sha256=$request.binding_sha256; binding_size_bytes=900L
        raw_manifest_sha256=$request.raw_manifest_sha256; raw_manifest_size_bytes=800L
        ordered_raw_report_set_sha256=$request.ordered_raw_report_set_sha256
        case_runtime_commitment_sha256=$request.case_runtime_commitment_sha256
        case_count=12; process_identity_count=24; release_bundle_schema='MCACE_RELEASE_BUNDLE_V4'
        release_bundle_manifest_sha256=$request.release_bundle_manifest_sha256
        release_bundle_manifest_size_bytes=700L
        release_bundle_sha256s_sha256=$request.release_bundle_sha256s_sha256
        release_bundle_sha256s_size_bytes=600L
        release_bundle_artifact_set_sha256=$request.release_bundle_artifact_set_sha256
        release_bundle_artifact_count=6
        matrix_product_jar_set_sha256=$request.matrix_product_jar_set_sha256
        matrix_product_jar_count=3; supervisor_independent=$true; signer_key_id=$keyId
        signer_trust_root_sha256=$rootSha; signature_algorithm='RSA_PKCS1_SHA256'
        test_fixture=$false; signature_base64=''
    }
    $payload = & $receiptModule { param($Value) Get-MatrixSupervisorReceiptSigningPayload $Value } $receipt
    $receipt.signature_base64 = [Convert]::ToBase64String($rsa.SignData($payload,'SHA256'))
    $trust = [pscustomobject]@{
        value=[pscustomobject]@{ key_id=$keyId }; document=[pscustomobject]@{ sha256=$rootSha }
        modulus=$public.Modulus; exponent=$public.Exponent
    }
    $validation = [pscustomobject]@{ value=$request; issued_at=$issued; expires_at=$expires }
    $accepted = & $receiptModule {
        param($Document,$Validation,$Trust)
        Assert-MatrixSupervisorReceipt $Document $Validation $Trust
    } ([pscustomobject]@{ value=$receipt }) $validation $trust
    Assert-True ([string]$accepted.value.operation_attempt_id -ceq [string]$request.operation_attempt_id) `
        'valid independently signed Matrix V4 supervisor receipt was rejected'

    $badSignature = $receipt.PSObject.Copy()
    $badSignature.signature_base64 = [Convert]::ToBase64String((New-Object byte[] 256))
    Assert-Throws {
        & $receiptModule { param($D,$V,$T) Assert-MatrixSupervisorReceipt $D $V $T } `
            ([pscustomobject]@{ value=$badSignature }) $validation $trust | Out-Null
    } 'MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_SIGNATURE_INVALID'
    $fixtureReceipt = $receipt.PSObject.Copy(); $fixtureReceipt.test_fixture = $true
    Assert-Throws {
        & $receiptModule { param($D,$V,$T) Assert-MatrixSupervisorReceipt $D $V $T } `
            ([pscustomobject]@{ value=$fixtureReceipt }) $validation $trust | Out-Null
    } 'MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_PROVENANCE_INVALID'
    $dependentReceipt = $receipt.PSObject.Copy(); $dependentReceipt.supervisor_independent = $false
    Assert-Throws {
        & $receiptModule { param($D,$V,$T) Assert-MatrixSupervisorReceipt $D $V $T } `
            ([pscustomobject]@{ value=$dependentReceipt }) $validation $trust | Out-Null
    } 'MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_PROVENANCE_INVALID'
    $expiredIssued = [DateTimeOffset]::UtcNow.AddMinutes(-20)
    $expiredAt = [DateTimeOffset]::UtcNow.AddMinutes(-10)
    $expiredRequest = $request.PSObject.Copy()
    $expiredRequest.challenge_issued_at = $expiredIssued.ToString('o')
    $expiredValidation = [pscustomobject]@{
        value=$expiredRequest; issued_at=$expiredIssued; expires_at=$expiredAt
    }
    $expiredReceipt = $receipt.PSObject.Copy()
    $expiredReceipt.challenge_issued_at = $expiredRequest.challenge_issued_at
    $expiredReceipt.signed_at = $expiredIssued.AddMinutes(1).ToString('o')
    $expiredReceipt.expires_at = $expiredAt.ToString('o')
    $expiredReceipt.signature_base64 = ''
    $expiredPayload = & $receiptModule {
        param($Value) Get-MatrixSupervisorReceiptSigningPayload $Value
    } $expiredReceipt
    $expiredReceipt.signature_base64 = [Convert]::ToBase64String(
        $rsa.SignData($expiredPayload,'SHA256'))
    $historicalAccepted = & $receiptModule {
        param($D,$V,$T) Assert-MatrixSupervisorReceipt $D $V $T
    } ([pscustomobject]@{ value=$expiredReceipt }) $expiredValidation $trust
    Assert-True ([string]$historicalAccepted.value.operation_attempt_id -ceq
            [string]$request.operation_attempt_id) `
        'historically valid Matrix V4 receipt was invalidated by the current wall clock'
    $badOrdering = $expiredReceipt.PSObject.Copy()
    $badOrdering.signed_at = $expiredAt.AddSeconds(1).ToString('o')
    Assert-Throws {
        & $receiptModule { param($D,$V,$T) Assert-MatrixSupervisorReceipt $D $V $T } `
            ([pscustomobject]@{ value=$badOrdering }) $expiredValidation $trust | Out-Null
    } 'MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_EXPIRED_OR_TIME_INVALID'
} finally {
    $rsa.Dispose()
    Remove-Module $receiptModule -Force -ErrorAction SilentlyContinue
}

$pinModule = New-Module -ScriptBlock ([scriptblock]::Create(
    "Set-StrictMode -Version Latest`n" +
    (Get-FunctionText $ast @('Get-MatrixApprovedSupervisorPin'))))
$pinName = 'MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256'
$savedMatrixPin = [Environment]::GetEnvironmentVariable($pinName,'Process')
try {
    [Environment]::SetEnvironmentVariable($pinName,$null,'Process')
    Assert-Throws {
        & $pinModule { param($Expected) $script:ExpectedMatrixSupervisorTrustRootSha256=$Expected; Get-MatrixApprovedSupervisorPin } ('f' * 64)
    } 'MCACE_RELEASE_MATRIX_APPROVED_SUPERVISOR_PIN_REQUIRED'
    [Environment]::SetEnvironmentVariable($pinName,('a' * 64),'Process')
    Assert-Throws {
        & $pinModule { param($Expected) $script:ExpectedMatrixSupervisorTrustRootSha256=$Expected; Get-MatrixApprovedSupervisorPin } ('b' * 64)
    } 'MCACE_RELEASE_MATRIX_SUPERVISOR_PIN_NOT_APPROVED'
    $approved = & $pinModule {
        param($Expected) $script:ExpectedMatrixSupervisorTrustRootSha256=$Expected
        Get-MatrixApprovedSupervisorPin
    } ('a' * 64)
    Assert-True ([string]$approved -ceq ('a' * 64)) 'approved Matrix supervisor pin was rejected'
} finally {
    [Environment]::SetEnvironmentVariable($pinName,$savedMatrixPin,'Process')
    Remove-Module $pinModule -Force -ErrorAction SilentlyContinue
}

$replayRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('mcace-readiness-matrix-replay-' + [Guid]::NewGuid().ToString('N'))
try {
    $replayEvidence = Join-Path $replayRoot 'docs/evidence'
    [IO.Directory]::CreateDirectory($replayEvidence) | Out-Null
    $currentReplayRelative = 'docs/evidence/server-version-process-matrix-current.json'
    Write-JsonNoBom (Join-Path $replayRoot $currentReplayRelative) ([ordered]@{
        schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V4'
        supervisor=[ordered]@{ operation_attempt_id='1' * 32; challenge_nonce='2' * 64 }
    })
    $otherReplayPath = Join-Path $replayEvidence 'server-version-process-matrix-other.json'
    Write-JsonNoBom $otherReplayPath ([ordered]@{
        schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V4'
        supervisor=[ordered]@{ operation_attempt_id='1' * 32; challenge_nonce='3' * 64 }
    })
    $replayStub = @'
function Read-StrictRepoJson([string]$Relative,[string]$Prefix,[string]$ExpectedLeaf='') {
    $absolute = Join-Path $script:repoRoot $Relative
    return [pscustomobject]@{ value=(Get-Content -LiteralPath $absolute -Raw | ConvertFrom-Json) }
}
'@
    $replayModule = New-Module -ScriptBlock ([scriptblock]::Create(
        "Set-StrictMode -Version Latest`n`$script:repoRoot='$($replayRoot.Replace("'","''"))'`n" +
        "`$script:evidenceRootRelative='docs/evidence'`n" + $replayStub + "`n" +
        (Get-FunctionText $ast @('Assert-MatrixNoSupervisorReplay'))))
    Assert-Throws {
        & $replayModule { param($Receipt,$Current) Assert-MatrixNoSupervisorReplay $Receipt $Current } `
            ([pscustomobject]@{ operation_attempt_id='1' * 32; challenge_nonce='2' * 64 }) `
            $currentReplayRelative
    } 'MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_REPLAY_REJECTED'
    Write-JsonNoBom $otherReplayPath ([ordered]@{
        schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V4'
        supervisor=[ordered]@{ operation_attempt_id='4' * 32; challenge_nonce='3' * 64 }
    })
    & $replayModule { param($Receipt,$Current) Assert-MatrixNoSupervisorReplay $Receipt $Current } `
        ([pscustomobject]@{ operation_attempt_id='1' * 32; challenge_nonce='2' * 64 }) `
        $currentReplayRelative
} finally {
    Remove-Module $replayModule -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $replayRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$provenanceText = Get-FunctionText $ast @('Test-SourceProvenance')
Assert-True ($provenanceText.Contains('docs/evidence/.+')) `
    'artifact-to-final provenance does not allow the evidence-only publication delta'
Assert-True (-not $provenanceText.Contains('.github/workflows/build.yml') -and
    -not $provenanceText.Contains('scripts/release-readiness.ps1')) `
    'artifact-to-final provenance still permits code or workflow changes'
Assert-True ($workflowSource.Contains('./scripts/test-publish-server-version-matrix-evidence.ps1')) `
    'CI does not run the Matrix V4 publisher regression'
foreach ($workflowToken in @(
        "&& 'release' || 'ci'",'deployment: false',
        'secrets.MCACE_MATRIX_SUPERVISOR_TRUST_ROOT_BASE64',
        'vars.MCACE_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256',
        'secrets.MCACE_FEDERATION_GUI_TRUST_ROOT_BASE64',
        'vars.MCACE_FEDERATION_GUI_TRUST_ROOT_SHA256',
        'secrets.MCACE_FEDERATION_POSTRUN_TRUST_ROOT_BASE64',
        'vars.MCACE_FEDERATION_POSTRUN_TRUST_ROOT_SHA256',
        'secrets.MCACE_VULCAN_SUPERVISOR_TRUST_ROOT_BASE64',
        'vars.MCACE_VULCAN_SUPERVISOR_TRUST_ROOT_SHA256',
        'vars.MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256',
        'vars.MCACE_AUTHORITY_OPENSSL_SHA256',
        'MCACE_PROTECTED_RELEASE_ENVIRONMENT',
        '-MatrixSupervisorTrustRootPath $matrixRoot',
        '-VisibleGuiTrustRootPath $guiRoot',
        '-PostRunSupervisorTrustRootPath $postRunRoot',
        '-VulcanSupervisorTrustRootPath $vulcanRoot',
        '-ExpectedVulcanSupervisorTrustRootSha256 $env:VULCAN_SUPERVISOR_TRUST_ROOT_SHA256',
        'MCACE_VULCAN_SUPERVISOR_TRUST_ROOT_SHA256=$env:VULCAN_SUPERVISOR_TRUST_ROOT_SHA256')) {
    Assert-True ($workflowSource.Contains($workflowToken)) `
        "protected release environment/trust-root workflow token missing: $workflowToken"
}
Assert-True (-not $workflowSource.Contains(
        'MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256=$(Get-FileHash') -and
        -not $workflowSource.Contains(
        'MCACE_RELEASE_APPROVED_FEDERATION_GUI_TRUST_ROOT_SHA256=$(Get-FileHash') -and
        -not $workflowSource.Contains(
        'MCACE_VULCAN_SUPERVISOR_TRUST_ROOT_SHA256=$(Get-FileHash')) `
    'protected workflow derives an approved trust anchor from the evidence under review'
$vulcanFunction = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-VulcanIndex'
}, $true))
Assert-True ($vulcanFunction.Count -eq 1) 'Assert-VulcanIndex is missing or duplicated'
$vulcanText = $vulcanFunction[0].Extent.Text
Assert-True ($vulcanText.Contains('MCACE_RELEASE_VULCAN_V2_DIAGNOSTIC_NOT_RELEASE_GRADE')) `
    'Vulcan V2 terminal diagnostic-only barrier is absent'
foreach($token in @('MCACE_VULCAN_GENUINE_EVENT_EVIDENCE_INDEX_V3',
        'Assert-VulcanV3Package','MCACE_RELEASE_VULCAN_V3_REPLAY_REJECTED',
        'MCACE_VULCAN_SUPERVISOR_TRUST_ROOT_SHA256','Test-SourceProvenance',
        'return [pscustomobject]')) {
    Assert-True ($vulcanText.Contains($token)) "Vulcan V3 readiness contract missing: $token"
}
Assert-True (-not $vulcanText.Contains('-RequireCurrentlyValidReceipt')) `
    'Vulcan immutable V3 evidence is incorrectly tied to current wall-clock receipt validity'

# Instantiate the same extracted validator used by protected readiness so any
# newly referenced helper must be explicitly included in the module contract.
$vulcanFactoryText = Get-FunctionText $ast @(
    'Get-ReadinessAstFunctionText','Get-ReadinessAstAssignmentText',
    'New-ReadinessVulcanV3ValidatorModule')
$vulcanFactoryText = $vulcanFactoryText.Replace(
    '$PSScriptRoot', "'$($PSScriptRoot.Replace("'","''"))'")
Invoke-Expression $vulcanFactoryText
$vulcanReadinessValidator = New-ReadinessVulcanV3ValidatorModule
try {
    Assert-True (& $vulcanReadinessValidator {
            $null -ne (Get-Command Assert-VulcanV3Package -ErrorAction SilentlyContinue) -and
            $null -ne (Get-Command Test-JsonArray -ErrorAction SilentlyContinue)
        }) 'protected Vulcan V3 validator extraction is incomplete'
} finally {
    Remove-Module $vulcanReadinessValidator -Force -ErrorAction SilentlyContinue
}

# Verify the exact eight-file directory shape independently from manifest semantics.
$entryModule = New-Module -ScriptBlock ([scriptblock]::Create(
    "Set-StrictMode -Version Latest`n" +
    (Get-FunctionText $ast @('Test-ExactReleaseBundleEntrySet'))))
$shapeRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('mcace-readiness-shape-' + [Guid]::NewGuid().ToString('N'))
$entryNames = @('mcace-client-fabric-1.21.11.jar','mcace-client-fabric-26.1.2.jar',
    'mcace-client-fabric-26.2.jar','mcace-server-velocity.jar',
    'mcace-server-bungeecord.jar','mcace-server-paper.jar',
    'release-manifest.properties','SHA256SUMS')
try {
    [IO.Directory]::CreateDirectory($shapeRoot) | Out-Null
    foreach ($name in $entryNames) {
        [IO.File]::WriteAllBytes((Join-Path $shapeRoot $name), [byte[]](1,2,3))
    }
    Assert-True (& $entryModule { param($Root,$Names) Test-ExactReleaseBundleEntrySet $Root $Names } `
        $shapeRoot $entryNames) 'exact eight-file bundle shape rejected'
    [IO.File]::WriteAllBytes((Join-Path $shapeRoot 'extra.bin'), [byte[]](4))
    Assert-True (-not (& $entryModule { param($Root,$Names) Test-ExactReleaseBundleEntrySet $Root $Names } `
        $shapeRoot $entryNames)) 'extra bundle entry accepted'
    Remove-Item -LiteralPath (Join-Path $shapeRoot 'extra.bin') -Force
    $directoryEntry = Join-Path $shapeRoot 'SHA256SUMS'
    Remove-Item -LiteralPath $directoryEntry -Force
    [IO.Directory]::CreateDirectory($directoryEntry) | Out-Null
    Assert-True (-not (& $entryModule { param($Root,$Names) Test-ExactReleaseBundleEntrySet $Root $Names } `
        $shapeRoot $entryNames)) 'nested bundle directory accepted'
    Remove-Item -LiteralPath $directoryEntry -Recurse -Force
    [IO.File]::WriteAllBytes($directoryEntry, [byte[]](1,2,3))
    $hidden = Join-Path $shapeRoot 'release-manifest.properties'
    [IO.File]::SetAttributes($hidden,[IO.FileAttributes]::Hidden)
    Assert-True (-not (& $entryModule { param($Root,$Names) Test-ExactReleaseBundleEntrySet $Root $Names } `
        $shapeRoot $entryNames)) 'hidden bundle entry accepted'
    [IO.File]::SetAttributes($hidden,[IO.FileAttributes]::Normal)
} finally {
    Remove-Module $entryModule -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $shapeRoot) {
        Get-ChildItem -LiteralPath $shapeRoot -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try { $_.Attributes=[IO.FileAttributes]::Normal } catch {}
        }
        Remove-Item -LiteralPath $shapeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Exercise Windows no-follow identity and path-chain checks with an actual junction.  Symlink
# creation is policy-dependent; an unavailable branch is explicitly reported rather than counted
# as strict coverage.
$identityModule = New-Module -ScriptBlock ([scriptblock]::Create(
    "Set-StrictMode -Version Latest`n" +
    (Get-FunctionText $ast @('Test-ReleaseWindowsPlatform','Initialize-ReleaseFileIdentityApi',
        'Assert-ReleasePathChainNoReparse','Get-ReleaseNoFollowFileIdentity'))))
$identityRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('mcace-readiness-identity-' + [Guid]::NewGuid().ToString('N'))
try {
    $real = Join-Path $identityRoot 'real'
    [IO.Directory]::CreateDirectory($real) | Out-Null
    $junction = Join-Path $identityRoot 'junction'
    $null = New-Item -ItemType Junction -Path $junction -Target $real -ErrorAction Stop
    Assert-Throws {
        $null = & $identityModule { param($Path) Assert-ReleasePathChainNoReparse $Path $true } $junction
    } 'MCACE_RELEASE_EVIDENCE_REPARSE_PATH_REJECTED'
    Assert-Throws {
        $null = & $identityModule { param($Path) Get-ReleaseNoFollowFileIdentity $Path -Directory } $junction
    } 'MCACE_RELEASE_NOFOLLOW_IDENTITY_FAILED'
    $symlink = Join-Path $identityRoot 'symlink'
    $createdSymlink = $false
    try {
        $null = New-Item -ItemType SymbolicLink -Path $symlink -Target $real -ErrorAction Stop
        $createdSymlink = $true
    } catch {
        Write-Output 'RELEASE_READINESS_V5_SYMLINK_COVERAGE_UNAVAILABLE|host privilege or policy denied symbolic-link creation'
    }
    if ($createdSymlink) {
        Assert-Throws {
            $null = & $identityModule { param($Path) Assert-ReleasePathChainNoReparse $Path $true } $symlink
        } 'MCACE_RELEASE_EVIDENCE_REPARSE_PATH_REJECTED'
        Assert-Throws {
            $null = & $identityModule { param($Path) Get-ReleaseNoFollowFileIdentity $Path -Directory } $symlink
        } 'MCACE_RELEASE_NOFOLLOW_IDENTITY_FAILED'
        $symlinkCovered = $true
    }
} finally {
    Remove-Module $identityModule -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $identityRoot) {
        Remove-Item -LiteralPath $identityRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# The active repository must remain fail-closed while release evidence is incomplete.  This is a
# runtime smoke of the actual script, not a source-only assertion.
$currentReport = Invoke-Readiness $repoRoot
Assert-True (-not [bool]$currentReport.release_ready) 'current repository unexpectedly became release-ready'
foreach ($name in @('fabric_gui_single_enablement_confirmation','fabric_federation_real_handoff',
        'vulcan_genuine_event','production_server_confirmed_authority',
        'protected_exact_release_bundle')) {
    Assert-Gate $currentReport $name $false
}

# Build an independent exact-commit repository to prove the protected bundle V4 + compatibility
# V2 + canonical artifact-source marker path can pass while all native runtime gates remain closed.
# Legacy bool-summary indexes are committed into the fixture and must not satisfy any gate.
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('mcace-readiness-v5-repo-' + [Guid]::NewGuid().ToString('N'))
try {
    $fixtureScripts = Join-Path $fixtureRoot 'scripts'
    $fixtureEvidence = Join-Path $fixtureRoot 'docs/evidence'
    [IO.Directory]::CreateDirectory($fixtureScripts) | Out-Null
    [IO.Directory]::CreateDirectory($fixtureEvidence) | Out-Null
    Copy-Item -LiteralPath $scriptPath -Destination (Join-Path $fixtureScripts 'release-readiness.ps1')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fabric-federation-gui-handoff-smoke.ps1') `
        -Destination (Join-Path $fixtureScripts 'fabric-federation-gui-handoff-smoke.ps1')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'platform-load-smoke.ps1') `
        -Destination (Join-Path $fixtureScripts 'platform-load-smoke.ps1')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'vulcan-genuine-event-smoke.ps1') `
        -Destination (Join-Path $fixtureScripts 'vulcan-genuine-event-smoke.ps1')
    & git -C $fixtureRoot init -q
    & git -C $fixtureRoot config user.name 'MCAce Readiness Fixture'
    & git -C $fixtureRoot config user.email 'fixture@invalid.local'
    & git -C $fixtureRoot add scripts
    & git -C $fixtureRoot commit -q -m 'artifact source fixture'
    Assert-True ($LASTEXITCODE -eq 0) 'artifact source fixture commit failed'
    $artifactCommit = (& git -C $fixtureRoot rev-parse HEAD).Trim().ToLowerInvariant()
    $markerPath = Join-Path $fixtureEvidence 'release-artifact-source.txt'
    [IO.File]::WriteAllBytes($markerPath, $ascii.GetBytes($artifactCommit + "`n"))
    Write-JsonNoBom (Join-Path $fixtureEvidence 'fabric-gui-consent-legacy.json') ([ordered]@{
        schema='MCACE_FABRIC_GUI_CONSENT_EVIDENCE_INDEX_V1'
        generated_at=[DateTimeOffset]::UtcNow.ToString('o'); source_commit=$artifactCommit
        all_checks_passed=$true
    })
    Write-JsonNoBom (Join-Path $fixtureEvidence 'federation-gui-handoff-legacy.json') ([ordered]@{
        schema='MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V2'
        generated_at=[DateTimeOffset]::UtcNow.ToString('o'); source_commit=$artifactCommit
        passed=$true
    })
    Write-JsonNoBom (Join-Path $fixtureEvidence 'vulcan-genuine-event-legacy.json') ([ordered]@{
        schema='MCACE_VULCAN_GENUINE_EVENT_EVIDENCE_INDEX_V1'
        generated_at=[DateTimeOffset]::UtcNow.ToString('o'); source_commit=$artifactCommit
        genuine_external_trigger_operator_attested=$true; passed=$true
    })
    Write-JsonNoBom (Join-Path $fixtureEvidence 'server-confirmed-production-legacy-v1.json') ([ordered]@{
        schema='MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V1'
        generated_at=[DateTimeOffset]::UtcNow.ToString('o'); source_commit=$artifactCommit
        all_cases_passed=$true; cleanup_all_zero=$true; server_confirmed_only=$true
        release_eligible=$true
    })
    Write-JsonNoBom (Join-Path $fixtureEvidence 'server-confirmed-production-legacy-v3.json') ([ordered]@{
        schema='MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V3'
        generated_at=[DateTimeOffset]::UtcNow.ToString('o'); source_commit=$artifactCommit
        operator_attests_genuine_provider_events=$true
        operator_attests_no_synthetic_injection=$true
        release_eligible=$true
    })
    Write-JsonNoBom (Join-Path $fixtureEvidence 'server-confirmed-production-manual-v4.json') ([ordered]@{
        schema='MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V4'
        generated_at=[DateTimeOffset]::UtcNow.ToString('o'); source_commit=$artifactCommit
        artifact_source_commit=$artifactCommit; product_version='0.0.1'
        evidence_class='EXTERNAL_SUPERVISOR_SIGNED_RAW_REVALIDATED_PRODUCTION_AUTHORITY'
        release_eligible=$true; capture_id='manual-capture'; operation_attempt_id='manual-attempt'
        all_cases_passed=$true; cleanup_all_zero=$true; server_confirmed_only=$true
    })
    & git -C $fixtureRoot add docs
    & git -C $fixtureRoot commit -q -m 'tracked release selector and adversarial legacy indexes'
    Assert-True ($LASTEXITCODE -eq 0) 'final fixture commit failed'
    $finalCommit = (& git -C $fixtureRoot rev-parse HEAD).Trim().ToLowerInvariant()
    Assert-True ($finalCommit -cne $artifactCommit) 'fixture source/final commits did not separate'
    $bundleRoot = Join-Path $fixtureRoot 'build/release-bundle'
    $bundle = New-TestReleaseBundle $bundleRoot $finalCommit $artifactCommit
    Write-CompatibilityReport $fixtureRoot $finalCommit $artifactCommit $bundle

    $protected = Invoke-Readiness $fixtureRoot -Protected
    Assert-Gate $protected 'protected_exact_release_bundle' $true
    Assert-Gate $protected 'fabric_gui_single_enablement_confirmation' $false
    Assert-Gate $protected 'fabric_federation_real_handoff' $false
    Assert-Gate $protected 'vulcan_genuine_event' $false
    Assert-Gate $protected 'production_server_confirmed_authority' $false

    # Exact 40 lowercase hex + LF is a hard selector, not a trim-tolerant text hint.
    [IO.File]::WriteAllBytes($markerPath, $ascii.GetBytes($artifactCommit.ToUpperInvariant() + "`n"))
    Assert-Gate (Invoke-Readiness $fixtureRoot -Protected) 'protected_exact_release_bundle' $false
    [IO.File]::WriteAllBytes($markerPath, $ascii.GetBytes($artifactCommit + "`n"))

    # The protected contract is content-bound to every final artifact and compatibility hash.
    $paperPath = Join-Path $bundleRoot 'mcace-server-paper.jar'
    $paperBytes = [IO.File]::ReadAllBytes($paperPath)
    $paperBytes[100] = $paperBytes[100] -bxor 0x5a
    [IO.File]::WriteAllBytes($paperPath,$paperBytes)
    Assert-Gate (Invoke-Readiness $fixtureRoot -Protected) 'protected_exact_release_bundle' $false
} finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($symlinkCovered) {
    Write-Output "RELEASE_READINESS_V5_STRICT_PASS|engine=$($PSVersionTable.PSEdition)-$($PSVersionTable.PSVersion)"
} else {
    Write-Output "RELEASE_READINESS_V5_PASS_WITH_SYMLINK_PERMISSION_GAP|engine=$($PSVersionTable.PSEdition)-$($PSVersionTable.PSVersion)"
}
