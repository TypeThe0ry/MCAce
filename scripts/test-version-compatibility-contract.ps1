[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'version-compatibility-contract-smoke.ps1'
$source = Get-Content -LiteralPath $scriptPath -Raw

foreach ($token in @(
        "MCACE_VERSION_COMPATIBILITY_EXECUTE_PASS",
        "MCACE_VERSION_COMPATIBILITY_REPORTONLY_PASS",
        "MCACE_COMPATIBILITY_CONTRACT_MODE_REQUIRED",
        "MCACE_COMPATIBILITY_NESTED_JAR_CONTRACT_MISMATCH",
        "ExpectedSourceCommit",
        "MCACE_COMPATIBILITY_SOURCE_COMMIT_MISMATCH",
        "'1.21.11'",
        "'26.1.2'",
        "'26.2'",
        "'1.21.1'",
        "'26.3'")) {
    if ($source.IndexOf($token, [StringComparison]::Ordinal) -lt 0) {
        throw "MCACE_VERSION_COMPATIBILITY_STATIC_TOKEN_MISSING|$token"
    }
}

if ($source -match "targetVersions\s*=.*1\.21\.1" -or
        $source -match "ValidateSet\([^)]*1\.21\.1") {
    throw 'MCACE_VERSION_COMPATIBILITY_LEGACY_TARGET_ACCEPTED'
}
if ($source -notmatch 'bundle_entry_count.*-ne 8' -or
        $source -notmatch 'unsupported_versions_are_fail_closed') {
    throw 'MCACE_VERSION_COMPATIBILITY_FAIL_CLOSED_ASSERTION_MISSING'
}

Write-Output 'MCACE_VERSION_COMPATIBILITY_STATIC_PASS'
