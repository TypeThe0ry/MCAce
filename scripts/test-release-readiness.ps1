[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scriptPath = Join-Path $PSScriptRoot 'release-readiness.ps1'
$source = Get-Content -LiteralPath $scriptPath -Raw
foreach ($required in @(
    'server_matrix_exact_source',
    'fabric_gui_single_enablement_confirmation',
    'fabric_federation_real_handoff',
    'vulcan_genuine_event',
    'production_server_confirmed_authority',
    'protected_exact_release_bundle',
    'MCACE_RELEASE_READINESS_BLOCKED',
    'current-source',
    'synthetic_event',
    'Test-SourceProvenance',
    'Test-ProtectedReleaseCiContext',
    'Test-BuildReleaseBundle',
    'protected_main_exact_commit_ci',
    'build/release-bundle',
    'GITHUB_ACTIONS',
    'GITHUB_REPOSITORY',
    'GITHUB_EVENT_NAME',
    'GITHUB_REF',
    'refs/tags/v0.0.1',
    'MCACE_PROTECTED_RELEASE_CI',
    'github/workflows/build',
    'scripts/version-compatibility-contract-smoke',
    'scripts/test-version-compatibility-contract',
    'merge-base --is-ancestor',
    'scripts/release-readiness'
)) {
    if ($source.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "RELEASE_READINESS_STATIC_ASSERTION_FAILED|$required"
    }
}

$workflowPath = Join-Path $repoRoot '.github/workflows/build.yml'
$workflow = Get-Content -LiteralPath $workflowPath -Raw
foreach ($required in @('refs/tags/v0.0.1', 'MCACE_PROTECTED_RELEASE_CI', 'Verify the release bundle compatibility contract')) {
    if ($workflow.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "RELEASE_WORKFLOW_STATIC_ASSERTION_FAILED|$required"
    }
}
if (@([regex]::Matches($workflow, 'refs/tags/v0\.0\.1')).Count -lt 4) {
    throw 'RELEASE_WORKFLOW_TAG_RELEASE_PATH_INCOMPLETE'
}

$testRoot = Join-Path $repoRoot 'build/release-readiness-test'
[void][IO.Directory]::CreateDirectory($testRoot)
$reportPath = Join-Path $testRoot 'blocked-report.json'
$stdoutPath = Join-Path $testRoot 'stdout.txt'
$stderrPath = Join-Path $testRoot 'stderr.txt'
foreach ($path in @($reportPath,$stdoutPath,$stderrPath)) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}
$pwsh = (Get-Command pwsh -ErrorAction Stop).Source
$process = Start-Process -FilePath $pwsh -WorkingDirectory $repoRoot -Wait -PassThru `
    -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath `
    -ArgumentList @('-NoProfile','-File',$scriptPath,'-ReportPath',$reportPath)
if ($process.ExitCode -ne 1) {
    throw "RELEASE_READINESS_EXPECTED_FAIL_CLOSED|$($process.ExitCode)"
}
if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
    throw 'RELEASE_READINESS_REPORT_MISSING'
}
$report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
if ($report.release_ready -ne $false -or @($report.blockers).Count -lt 3) {
    throw 'RELEASE_READINESS_FAIL_CLOSED_REPORT_INVALID'
}
if (@($report.blockers | Where-Object { $_ -ceq 'protected_exact_release_bundle' }).Count -ne 1) {
    throw 'RELEASE_READINESS_PROTECTED_MAIN_BUNDLE_MUST_FAIL_OUTSIDE_CI'
}
Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
Write-Output 'RELEASE_READINESS_STATIC_TEST_PASS'
