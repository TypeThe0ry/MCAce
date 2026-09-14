[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceCommit,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ArtifactSourceCommit,
    [string]$BundleRoot = 'build/release-bundle',
    [string]$CompatibilityReportPath = 'build/compatibility-contract/report.json',
    [string]$ReportPath = 'build/release-readiness/core-report.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Fail([string]$Code) { throw "MCACE_CORE_RELEASE_$Code" }
function Abs([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}
function Sha([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function RequireFile([string]$Path, [string]$Code) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail $Code }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "${Code}_REPARSE" }
}
function ReadProperties([string]$Path) {
    RequireFile $Path 'MANIFEST_REQUIRED'
    $out = [ordered]@{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $i = $line.IndexOf('=')
        if ($i -lt 1) { Fail 'MANIFEST_INVALID' }
        $key = $line.Substring(0,$i)
        if ($out.Contains($key)) { Fail 'MANIFEST_DUPLICATE_KEY' }
        $out[$key] = $line.Substring($i+1)
    }
    return [pscustomobject]$out
}

$head = (& git -C $repoRoot rev-parse HEAD).Trim().ToLowerInvariant()
if ($head -cne $SourceCommit) { Fail 'HEAD_MISMATCH' }
if (@(& git -C $repoRoot status --porcelain=v1 --untracked-files=all).Count -ne 0) { Fail 'WORKTREE_DIRTY' }
& git -C $repoRoot cat-file -e "$ArtifactSourceCommit^{commit}" 2>$null
if ($LASTEXITCODE -ne 0) { Fail 'ARTIFACT_SOURCE_UNKNOWN' }
$base = (& git -C $repoRoot merge-base $ArtifactSourceCommit $SourceCommit).Trim().ToLowerInvariant()
if ($base -cne $ArtifactSourceCommit) { Fail 'ARTIFACT_SOURCE_NOT_ANCESTOR' }

$marker = Abs 'docs/evidence/release-artifact-source.txt'
RequireFile $marker 'ARTIFACT_MARKER_REQUIRED'
$markerText = [IO.File]::ReadAllText($marker, [Text.Encoding]::ASCII)
if ($markerText -cne "$ArtifactSourceCommit`n") { Fail 'ARTIFACT_MARKER_MISMATCH' }

$bundle = Abs $BundleRoot
if (-not (Test-Path -LiteralPath $bundle -PathType Container)) { Fail 'BUNDLE_REQUIRED' }
$expected = @(
    'mcace-client-fabric-1.21.11.jar',
    'mcace-client-fabric-26.1.2.jar',
    'mcace-client-fabric-26.2.jar',
    'mcace-server-velocity.jar',
    'mcace-server-bungeecord.jar',
    'mcace-server-paper.jar',
    'release-manifest.properties',
    'SHA256SUMS'
)
$actual = @(Get-ChildItem -LiteralPath $bundle -Force | ForEach-Object Name | Sort-Object)
if (($actual -join '|') -cne (($expected | Sort-Object) -join '|')) { Fail 'BUNDLE_ENTRY_SET_INVALID' }
$manifest = ReadProperties (Join-Path $bundle 'release-manifest.properties')
if ($manifest.schema -cne 'MCACE_RELEASE_BUNDLE_V4' -or
    $manifest.bundle_profile -cne 'RELEASE' -or
    $manifest.release_identity -cne 'true' -or
    $manifest.product_version -cne '0.0.1' -or
    $manifest.source_commit -cne $SourceCommit -or
    $manifest.artifact_source_commit -cne $ArtifactSourceCommit -or
    $manifest.deployable_count -ne '6' -or $manifest.bundle_entry_count -ne '8') {
    Fail 'MANIFEST_IDENTITY_INVALID'
}

$checksumLines = Get-Content -LiteralPath (Join-Path $bundle 'SHA256SUMS')
foreach ($name in $expected | Where-Object { $_ -like '*.jar' }) {
    $path = Join-Path $bundle $name
    RequireFile $path 'ARTIFACT_REQUIRED'
    $line = @($checksumLines | Where-Object { $_ -match ('^[0-9a-f]{64}  ' + [regex]::Escape($name) + '$') })
    if ($line.Count -ne 1) { Fail "CHECKSUM_MISSING_$($name.Replace('.','_'))" }
    $expectedHash = ([string]$line[0]).Substring(0,64)
    if ((Sha $path) -cne $expectedHash) { Fail "CHECKSUM_MISMATCH_$($name.Replace('.','_'))" }
}

$compatPath = Abs $CompatibilityReportPath
RequireFile $compatPath 'COMPATIBILITY_REPORT_REQUIRED'
$compat = Get-Content -Raw -LiteralPath $compatPath | ConvertFrom-Json
if ($compat.schema -cne 'MCACE_VERSION_COMPATIBILITY_CONTRACT_V2' -or
    $compat.source_commit -cne $SourceCommit -or
    $compat.artifact_source_commit -cne $ArtifactSourceCommit -or
    $compat.target_count -ne 3 -or $compat.exact_bundle_entry_count -ne 8 -or
    $compat.passed -ne $true) { Fail 'COMPATIBILITY_REPORT_INVALID' }

$report = [ordered]@{
    schema='MCACE_CORE_RELEASE_READINESS_V1'
    generated_at=[DateTimeOffset]::Now.ToString('o')
    release_ready=$true
    source_commit=$SourceCommit
    artifact_source_commit=$ArtifactSourceCommit
    product_version='0.0.1'
    bundle_root=$BundleRoot
    bundle_entries=8
    compatibility_targets=3
    extended_certification='PENDING_EXTERNAL_EVIDENCE'
    interpretation='Core release is executable and source-bound. Extended GUI/Federation/Vulcan/Authority evidence remains a separate certification layer.'
}
$reportPath = Abs $ReportPath
[IO.Directory]::CreateDirectory((Split-Path -Parent $reportPath)) | Out-Null
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8
Write-Output "MCACE_CORE_RELEASE_READINESS_PASS|$reportPath"
