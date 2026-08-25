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
    # when the descendant changes are documentation/evidence or this gate's own
    # static harness. Any product, build, dependency, workflow, or runtime
    # source change requires a fresh exact-source matrix. Allowed gate file:
    # scripts/release-readiness.ps1 (and its static test companion).
    & git -C $repoRoot merge-base --is-ancestor ([string]$Value) $Current 2>$null
    if ($LASTEXITCODE -ne 0) { return $false }
    $changed = @(& git -C $repoRoot diff --name-only ("$Value..$Current") 2>$null)
    if ($LASTEXITCODE -ne 0) { return $false }
    foreach ($path in $changed) {
        $normalized = ([string]$path).Replace('\','/')
        if ($normalized -notmatch '^(README\.md|README_CN\.md|docs/|scripts/release-readiness\.ps1$|scripts/test-release-readiness\.ps1$)') {
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
$matrixIndexPath = 'docs/evidence/server-version-process-matrix-2026-08-25-65731aa.json'
$matrixIndex = Read-JsonFile $matrixIndexPath
$matrixTripletRoot = 'docs/evidence/server-version-process-matrix/2026-08-25T00-54-47-3783015Z'
$matrixReport = Read-JsonFile (Join-Path $matrixTripletRoot 'report.json')
$matrixBinding = Read-JsonFile (Join-Path $matrixTripletRoot 'binding.json')
$matrixCommit = Read-JsonFile (Join-Path $matrixTripletRoot 'commit.json')
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
$guiTargets = @('1.21.11','26.1.2','26.2')
$guiTargetPass = @($guiEvidence | Where-Object {
    (Test-SourceProvenance $_.source_commit $requestedCommit) -and
    (Test-Boolean $_.human_confirmation) -and
    (Test-Boolean $_.explicit_file_consent_accepted) -and
    (Test-Boolean $_.game_render_frame_consent_accepted) -and
    (Test-Boolean $_.fabric_gui_coverage) -and
    (Test-Boolean $_.fabric_evidence_coverage)
})
$guiPass = $guiTargetPass.Count -eq 3 -and
    @($guiTargetPass | Select-Object -ExpandProperty fabric_target -Unique).Count -eq 3 -and
    @($guiTargetPass | Where-Object { $guiTargets -contains [string]$_.fabric_target }).Count -eq 3
$guiDetail = if ($guiPass) { 'three targets have two human-approved visible decisions each' } else {
    "found $($guiTargetPass.Count)/3 current-source passing target records; stale or diagnostic attempts do not count"
}
Add-Gate $gates 'fabric_gui_six_human_decisions' $guiPass 'docs/evidence/fabric-gui-consent-*.json' $guiDetail

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
$releasePass = @($releaseEvidence | Where-Object {
    (Test-SourceProvenance $_.source_commit $requestedCommit) -and
    (Test-Boolean $_.release_identity) -and
    [string]$_.product_version -ceq '0.0.1' -and
    [int]$_.deployable_count -eq 6 -and
    [int]$_.bundle_entry_count -eq 8 -and
    (Test-Boolean $_.sha256sums_verified) -and
    (Test-Boolean $_.compatibility_passed)
}).Count -gt 0
$releaseDetail = if ($releasePass) { 'current-source exact-eight release bundle is independently verified' } else {
    'no current-source protected-main exact-eight release bundle evidence'
}
Add-Gate $gates 'protected_exact_release_bundle' $releasePass 'docs/evidence/release-bundle-*.json' $releaseDetail

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
