[CmdletBinding()]
param(
    [string]$SourceCommit,
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function ConvertTo-AbsoluteRepoPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}

function Read-JsonFile([string]$Path) {
    $resolved = ConvertTo-AbsoluteRepoPath $Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { return $null }
    try { return (Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json) }
    catch { throw "MCACE_RELEASE_READINESS_INVALID_JSON|$resolved|$($_.Exception.Message)" }
}

function Get-RepoHead {
    $value = (& git -C $repoRoot rev-parse HEAD 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or $value -notmatch '^[0-9a-f]{40}$') {
        throw 'MCACE_RELEASE_READINESS_GIT_HEAD_UNAVAILABLE'
    }
    return $value.ToLowerInvariant()
}

function Get-RepoStatus {
    return @(& git -C $repoRoot status --porcelain 2>$null)
}

function Test-StringEqual([object]$Value, [string]$Expected) {
    return $null -ne $Value -and [string]$Value -ceq $Expected
}

function Test-Boolean([object]$Value) {
    return $Value -is [bool] -and [bool]$Value
}

function Read-PropertiesFile([string]$Path) {
    $resolved = ConvertTo-AbsoluteRepoPath $Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { return $null }
    $properties = [ordered]@{}
    foreach ($line in @(Get-Content -LiteralPath $resolved)) {
        $text = ([string]$line).Trim()
        if ($text.Length -eq 0 -or $text.StartsWith('#') -or $text.StartsWith('!')) { continue }
        $separator = $text.IndexOf('=')
        if ($separator -lt 1) { return $null }
        $key = $text.Substring(0, $separator).Trim()
        $value = $text.Substring($separator + 1).Trim()
        if ($key.Length -eq 0 -or $properties.Contains($key)) { return $null }
        $properties[$key] = $value
    }
    return [pscustomobject]$properties
}

function Test-ProtectedReleaseCiContext {
    return [string]$env:GITHUB_ACTIONS -ceq 'true' -and
        [string]$env:GITHUB_REPOSITORY -ceq 'TypeThe0ry/MCAce' -and
        [string]$env:GITHUB_EVENT_NAME -ceq 'push' -and
        ([string]$env:GITHUB_REF -ceq 'refs/heads/main' -or
            [string]$env:GITHUB_REF -ceq 'refs/tags/v0.0.1') -and
        [string]$env:MCACE_PROTECTED_RELEASE_CI -ceq 'true'
}

function Test-BuildReleaseBundle([string]$BundleRoot, [string]$ExpectedCommit) {
    $root = ConvertTo-AbsoluteRepoPath $BundleRoot
    $manifestPath = Join-Path $root 'release-manifest.properties'
    $sumsPath = Join-Path $root 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $root -PathType Container) -or
            -not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $sumsPath -PathType Leaf)) {
        return $false
    }
    $manifest = Read-PropertiesFile $manifestPath
    if ($null -eq $manifest -or
            [string]$manifest.schema -cne 'MCACE_RELEASE_BUNDLE_V3' -or
            [string]$manifest.bundle_profile -cne 'RELEASE' -or
            [string]$manifest.release_identity -cne 'true' -or
            [string]$manifest.product_version -cne '0.0.1' -or
            [int]$manifest.deployable_count -ne 6 -or
            [int]$manifest.bundle_entry_count -ne 8 -or
            [string]$manifest.source_commit -cne $ExpectedCommit) {
        return $false
    }
    $jarNames = @(
        'mcace-client-fabric-1.21.11.jar',
        'mcace-client-fabric-26.1.2.jar',
        'mcace-client-fabric-26.2.jar',
        'mcace-server-velocity.jar',
        'mcace-server-bungeecord.jar',
        'mcace-server-paper.jar'
    )
    $expectedNames = @($jarNames + 'release-manifest.properties' + 'SHA256SUMS' | Sort-Object)
    $actualNames = @(Get-ChildItem -LiteralPath $root -File | Select-Object -ExpandProperty Name | Sort-Object)
    if ((@($actualNames) -join '|') -cne (@($expectedNames) -join '|')) { return $false }
    $sumLines = @(Get-Content -LiteralPath $sumsPath)
    if (@($sumLines).Count -ne 6) { return $false }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($line in $sumLines) {
        $parts = ([string]$line) -split '\s+', 2
        if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[0-9a-fA-F]{64}$' -or
                $parts[1] -notin $jarNames -or -not $seen.Add($parts[1])) { return $false }
        $path = Join-Path $root $parts[1]
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne $parts[0].ToLowerInvariant()) { return $false }
    }
    if ($seen.Count -ne 6) { return $false }
    $compatibilityReport = Read-JsonFile 'build/compatibility-contract/report.json'
    return $null -ne $compatibilityReport -and
        (Test-StringEqual $compatibilityReport.source_commit $ExpectedCommit) -and
        (Test-Boolean $compatibilityReport.passed) -and
        [int]$compatibilityReport.target_count -eq 3 -and
        [int]$compatibilityReport.exact_bundle_entry_count -eq 8 -and
        (Test-Boolean $compatibilityReport.unsupported_versions_are_fail_closed) -and
        @($compatibilityReport.targets).Count -eq 3 -and
        @($compatibilityReport.targets | Where-Object { -not (Test-Boolean $_.passed) }).Count -eq 0
}

function Add-Gate {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$List,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][string]$Evidence,
        [Parameter(Mandatory)][string]$Detail
    )
    [void]$List.Add([pscustomobject][ordered]@{
        name = $Name
        passed = $Passed
        evidence = $Evidence
        detail = $Detail
    })
}

function Test-SourceProvenance([object]$Value, [string]$Current) {
    if ($null -eq $Value -or [string]$Value -notmatch '^[0-9a-f]{40}$' -or
            $Current -notmatch '^[0-9a-f]{40}$') {
        return $false
    }
    if (Test-StringEqual $Value $Current) { return $true }

    # Evidence is allowed to be committed after the tested product source only
    # when the descendant changes are documentation/evidence or release-gate
    # harness changes. Any product, dependency, or runtime source change
    # requires a fresh exact-source matrix. The workflow and compatibility
    # scripts below only validate/package already-built artifacts; they do not
    # change the server/client runtime under test.
    & git -C $repoRoot merge-base --is-ancestor ([string]$Value) $Current 2>$null
    if ($LASTEXITCODE -ne 0) { return $false }
    $changed = @(& git -C $repoRoot diff --name-only ("$Value..$Current") 2>$null)
    if ($LASTEXITCODE -ne 0) { return $false }
    foreach ($path in $changed) {
        $normalized = ([string]$path).Replace('\','/')
        if ($normalized -notmatch '^(README\.md|README_CN\.md|docs/|\.github/workflows/build\.yml$|scripts/release-readiness\.ps1$|scripts/test-release-readiness\.ps1$|scripts/version-compatibility-contract-smoke\.ps1$|scripts/test-version-compatibility-contract\.ps1$)') {
            return $false
        }
    }
    return $true
}

if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $repoRoot 'build/release-readiness/report.json'
}
$ReportPath = ConvertTo-AbsoluteRepoPath $ReportPath
$reportDirectory = Split-Path -Parent $ReportPath
[void][IO.Directory]::CreateDirectory($reportDirectory)

$head = Get-RepoHead
$requestedCommit = if ([string]::IsNullOrWhiteSpace($SourceCommit)) {
    $head
} else {
    $SourceCommit.Trim().ToLowerInvariant()
}
if ($requestedCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'MCACE_RELEASE_READINESS_SOURCE_COMMIT_INVALID'
}

$gates = [System.Collections.Generic.List[object]]::new()
$matrixEvidenceRoot = Join-Path $repoRoot 'docs/evidence'
$matrixIndexCandidates = [System.Collections.Generic.List[object]]::new()
if (Test-Path -LiteralPath $matrixEvidenceRoot -PathType Container) {
    foreach ($candidateFile in @(Get-ChildItem -LiteralPath $matrixEvidenceRoot -File -Filter 'server-version-process-matrix-2026-08-25-*.json')) {
        $candidate = Read-JsonFile $candidateFile.FullName
        if ($null -eq $candidate -or
                [string]$candidate.schema -cne 'MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V1' -or
                [string]$candidate.source_commit -notmatch '^[0-9a-f]{40}$' -or
                [string]$candidate.canonical_run -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{7}Z$') {
            continue
        }
        try {
            $generatedAt = [DateTimeOffset]::Parse(
                [string]$candidate.generated_at,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind)
        } catch {
            continue
        }
        [void]$matrixIndexCandidates.Add([pscustomobject]@{
            path = $candidateFile.FullName
            value = $candidate
            generated_at = $generatedAt
        })
    }
}
$selectedMatrix = @($matrixIndexCandidates | Where-Object { [string]$_.value.source_commit -ceq $requestedCommit } |
    Sort-Object generated_at -Descending | Select-Object -First 1)
if ($selectedMatrix.Count -eq 0) {
    $selectedMatrix = @($matrixIndexCandidates | Sort-Object generated_at -Descending | Select-Object -First 1)
}
$matrixIndexPath = if ($selectedMatrix.Count -gt 0) {
    ([string]$selectedMatrix[0].path).Substring($repoRoot.Length + 1).Replace('\','/')
} else {
    'docs/evidence/server-version-process-matrix-2026-08-25-*.json'
}
$matrixIndex = if ($selectedMatrix.Count -gt 0) { $selectedMatrix[0].value } else { $null }
$matrixTripletRoot = if ($null -ne $matrixIndex -and
        [string]$matrixIndex.canonical_run -match '^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{7}Z$') {
    Join-Path 'docs/evidence/server-version-process-matrix' ([string]$matrixIndex.canonical_run)
} else { $null }
$matrixReport = if ($null -ne $matrixTripletRoot) { Read-JsonFile (Join-Path $matrixTripletRoot 'report.json') } else { $null }
$matrixBinding = if ($null -ne $matrixTripletRoot) { Read-JsonFile (Join-Path $matrixTripletRoot 'binding.json') } else { $null }
$matrixCommit = if ($null -ne $matrixTripletRoot) { Read-JsonFile (Join-Path $matrixTripletRoot 'commit.json') } else { $null }
$matrixPass = (
    ($null -ne $matrixIndex) -and
    ($null -ne $matrixReport) -and
    ($null -ne $matrixBinding) -and
    ($null -ne $matrixCommit) -and
    (Test-SourceProvenance $matrixIndex.source_commit $requestedCommit) -and
    (Test-Boolean $matrixIndex.result.all_cases_passed) -and
    (Test-Boolean $matrixIndex.result.cleanup_all_zero) -and
    ([int]$matrixIndex.result.expected_case_count -eq 12) -and
    ([int]$matrixIndex.result.observed_case_count -eq 12) -and
    (Test-StringEqual $matrixIndex.report_only.result 'SERVER_VERSION_PROCESS_MATRIX_REPORT_ONLY_PASS') -and
    (Test-Boolean $matrixReport.all_cases_passed) -and
    (Test-Boolean $matrixReport.cleanup_all_zero) -and
    (Test-Boolean $matrixBinding.passed) -and
    (Test-Boolean $matrixCommit.committed)
)
$matrixDetail = if ($null -eq $matrixIndex) {
    'current Helio matrix evidence index is missing'
} elseif (-not (Test-SourceProvenance $matrixIndex.source_commit $requestedCommit)) {
    "matrix evidence is bound to $($matrixIndex.source_commit), requested source is $requestedCommit"
} elseif (-not (Test-StringEqual $matrixIndex.source_commit $requestedCommit)) {
    "matrix evidence is bound to tested source $($matrixIndex.source_commit); current descendant contains only docs/evidence and release-gate harness changes"
} elseif (-not $matrixPass) {
    'matrix triplet/result fields are incomplete or failed'
} else {
    '12/12 Helio matrix, cleanup zero, and ReportOnly pass'
}
Add-Gate $gates 'server_matrix_exact_source' $matrixPass $matrixIndexPath $matrixDetail

$guiEvidence = @()
$guiRoot = Join-Path $repoRoot 'docs/evidence'
if (Test-Path -LiteralPath $guiRoot -PathType Container) {
    foreach ($file in @(Get-ChildItem -LiteralPath $guiRoot -File -Filter 'fabric-gui-consent-*.json')) {
        $item = Read-JsonFile $file.FullName
        if ($null -ne $item) { $guiEvidence += $item }
    }
}
$guiTargetPass = @($guiEvidence | Where-Object {
    (Test-SourceProvenance $_.source_commit $requestedCommit) -and
    (Test-Boolean $_.human_confirmation) -and
    (Test-Boolean $_.single_enablement_confirmation_accepted) -and
    (Test-Boolean $_.enablement_ui_rendered) -and
    (Test-Boolean $_.mca_ce_enabled) -and
    (Test-Boolean $_.no_confirmation_disabled) -and
    ([int]$_.ui_confirmation_count -eq 1) -and
    (Test-Boolean $_.fabric_gui_coverage)
})
$guiPass = $guiTargetPass.Count -gt 0
$guiDetail = if ($guiPass) {
    'one current-source visible MCAce enablement approval is recorded; no per-feature confirmation is required'
} else {
    'no current-source single enablement approval with fail-closed disabled behavior is recorded'
}
Add-Gate $gates 'fabric_gui_single_enablement_confirmation' $guiPass 'docs/evidence/fabric-gui-consent-*.json' $guiDetail

$federationEvidence = @()
foreach ($file in @(Get-ChildItem -LiteralPath $guiRoot -File -Filter 'federation-gui-handoff-*.json' -ErrorAction SilentlyContinue)) {
    $item = Read-JsonFile $file.FullName
    if ($null -ne $item) { $federationEvidence += $item }
}
$federationPass = @($federationEvidence | Where-Object {
    (Test-SourceProvenance $_.source_commit $requestedCommit) -and
    (Test-Boolean $_.real_source_to_target_gui_handoff) -and
    (Test-Boolean $_.source_export_approved) -and
    (Test-Boolean $_.target_import_approved) -and
    (Test-Boolean $_.target_session_alive_through_expiry) -and
    (Test-Boolean $_.fabric_gui_coverage)
}).Count -gt 0
$federationDetail = if ($federationPass) { 'current-source source export to target import handoff is recorded' } else {
    'no current-source real GUI source-to-target handoff record with both approvals and expiry proof'
}
Add-Gate $gates 'fabric_federation_real_handoff' $federationPass 'docs/evidence/federation-gui-handoff-*.json' $federationDetail

$vulcanEvidence = @()
foreach ($file in @(Get-ChildItem -LiteralPath $guiRoot -File -Filter 'vulcan-genuine-event-*.json' -ErrorAction SilentlyContinue)) {
    $item = Read-JsonFile $file.FullName
    if ($null -ne $item) { $vulcanEvidence += $item }
}
$vulcanPass = @($vulcanEvidence | Where-Object {
    (Test-SourceProvenance $_.source_commit $requestedCommit) -and
    (Test-Boolean $_.genuine_external_trigger) -and
    (-not (Test-Boolean $_.synthetic_event)) -and
    (Test-Boolean $_.real_behavior_event_delivery_coverage) -and
    (Test-Boolean $_.paper_plugin_enablement_coverage) -and
    (Test-Boolean $_.report_only_validated)
}).Count -gt 0
$vulcanDetail = if ($vulcanPass) { 'current-source licensed Vulcan genuine event is recorded' } else {
    'licensed current-source Vulcan enablement and genuine external event are absent'
}
Add-Gate $gates 'vulcan_genuine_event' $vulcanPass 'docs/evidence/vulcan-genuine-event-*.json' $vulcanDetail

$authorityEvidence = @()
foreach ($file in @(Get-ChildItem -LiteralPath $guiRoot -File -Filter 'server-confirmed-production-*.json' -ErrorAction SilentlyContinue)) {
    $item = Read-JsonFile $file.FullName
    if ($null -ne $item) { $authorityEvidence += $item }
}
$authorityPass = @($authorityEvidence | Where-Object {
    (Test-SourceProvenance $_.source_commit $requestedCommit) -and
    (Test-Boolean $_.provider_profile_key_topology_frozen) -and
    (Test-Boolean $_.real_process_matrix_passed) -and
    (Test-Boolean $_.action_ceiling_frozen)
}).Count -gt 0
$authorityDetail = if ($authorityPass) { 'production provider/profile/key/topology/action ceiling and real process matrix are frozen' } else {
    'production SERVER_CONFIRMED authority freeze and real producer matrix are absent'
}
Add-Gate $gates 'production_server_confirmed_authority' $authorityPass 'docs/evidence/server-confirmed-production-*.json' $authorityDetail

$releaseEvidence = @()
foreach ($file in @(Get-ChildItem -LiteralPath $guiRoot -File -Filter 'release-bundle-*.json' -ErrorAction SilentlyContinue)) {
    $item = Read-JsonFile $file.FullName
    if ($null -ne $item) { $releaseEvidence += $item }
}
$releaseEvidencePass = @($releaseEvidence | Where-Object {
    (Test-SourceProvenance $_.source_commit $requestedCommit) -and
    (Test-Boolean $_.protected_main_exact_commit_ci) -and
    (Test-Boolean $_.release_identity) -and
    [string]$_.product_version -ceq '0.0.1' -and
    [int]$_.deployable_count -eq 6 -and
    [int]$_.bundle_entry_count -eq 8 -and
    (Test-Boolean $_.sha256sums_verified) -and
    (Test-Boolean $_.compatibility_passed)
}).Count -gt 0
$releaseBuildPass = (Test-ProtectedReleaseCiContext) -and
    (Test-StringEqual $head $requestedCommit) -and
    (Test-BuildReleaseBundle 'build/release-bundle' $requestedCommit)
$releasePass = $releaseEvidencePass -or $releaseBuildPass
$releaseDetail = if ($releaseBuildPass) {
    'protected main/tag release CI verified the current exact-commit build/release-bundle on disk, including SHA256SUMS and 3/3 compatibility'
} elseif ($releaseEvidencePass) {
    'current-source protected-main exact-eight release evidence is independently verified'
} else {
    'no current-source protected-main/tag exact-eight release bundle evidence or protected release CI build bundle'
}
Add-Gate $gates 'protected_exact_release_bundle' $releasePass 'build/release-bundle or docs/evidence/release-bundle-*.json' $releaseDetail

$clean = (Get-RepoStatus).Count -eq 0
Add-Gate $gates 'clean_worktree' $clean 'git status --porcelain' $(if ($clean) { 'worktree is clean' } else { 'uncommitted changes are present' })

$ready = @($gates | Where-Object { -not $_.passed }).Count -eq 0
$result = [pscustomobject][ordered]@{
    schema = 'MCACE_RELEASE_READINESS_V1'
    generated_at = [DateTimeOffset]::Now.ToString('o')
    source_commit = $requestedCommit
    observed_head = $head
    release_ready = $ready
    gates = @($gates)
    blockers = @($gates | Where-Object { -not $_.passed } | ForEach-Object { $_.name })
    interpretation = if ($ready) {
        'All release gates are proven for the requested exact source; protected-main release actions may proceed.'
    } else {
        'Fail-closed: one or more release gates are missing, stale, or not bound to the requested exact source.'
    }
}
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
if ($ready) {
    Write-Output "MCACE_RELEASE_READINESS_PASS|$ReportPath"
    exit 0
}
Write-Output "MCACE_RELEASE_READINESS_BLOCKED|$ReportPath"
$result.blockers | ForEach-Object { Write-Output "MCACE_RELEASE_READINESS_BLOCKER|$_" }
exit 1
