[CmdletBinding()]
param(
    [ValidateSet('Velocity', 'Bungee', 'Both')]
    [string]$Proxy = 'Both'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$gradle = Join-Path $repoRoot 'gradlew.bat'
$velocityTests = @(
    'com.ellan.mcace.runtime.RealProxyDispositionMatrixGateTest.velocityMonitorLimitSyntheticExactManifestIsInert',
    'com.ellan.mcace.runtime.RealProxyDispositionMatrixGateTest.velocityEnforceLimitSyntheticExactManifestRoutesOnlyToLimited',
    'com.ellan.mcace.runtime.RealProxyDispositionMatrixGateTest.velocityEnforceQuarantineSyntheticExactManifestRoutesOnlyToQuarantine'
)
$bungeePhaseTwoTests = @(
    'com.ellan.mcace.runtime.RealProxyDispositionMatrixGateTest.bungeeMonitorLimitSyntheticExactManifestIsInert',
    'com.ellan.mcace.runtime.RealProxyDispositionMatrixGateTest.bungeeEnforceLimitSyntheticExactManifestRoutesOnlyToLimited',
    'com.ellan.mcace.runtime.RealProxyDispositionMatrixGateTest.bungeeEnforceQuarantineSyntheticExactManifestRoutesOnlyToQuarantine'
)
$tests = switch ($Proxy) {
    'Velocity' { $velocityTests }
    'Bungee' { $bungeePhaseTwoTests }
    default { @($velocityTests) + @($bungeePhaseTwoTests) }
}

# Deliberately sequential: real proxies and disposable Paper backends never overlap.
foreach ($test in $tests) {
    & $gradle ':mcace-runtime-integration:test' '--tests' $test '-Dmcace.runtime.disposition.enabled=true' '--rerun-tasks' '--no-build-cache' '--no-daemon' '--max-workers=1' '--console=plain'
    if ($LASTEXITCODE -ne 0) {
        throw "MCAce disposition proxy matrix Phase-2 gate failed: $test"
    }
}

Write-Output 'DISPOSITION_PROXY_MATRIX_PHASE_TWO_PARTIAL_PASS|build/runtime-disposition-matrix/runs/'
