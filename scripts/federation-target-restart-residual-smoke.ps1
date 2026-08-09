[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$gradle = Join-Path $repoRoot 'gradlew.bat'
$test = 'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.federationVelocityTargetRestartResidualReplayRealProcessGate'

Write-Host "MCAce federation target-restart residual gate: $test"
& $gradle '-Dmcace.runtime.federation.restart.enabled=true' ':mcace-runtime-integration:test' `
    '--tests' $test '--rerun-tasks' '--no-build-cache' '--no-daemon' '--console=plain'
if ($LASTEXITCODE -ne 0) {
    throw "MCAce federation target-restart residual gate failed: $test"
}

Write-Output 'FEDERATION_TARGET_RESTART_RESIDUAL_PASS|build/runtime-federation-target-restart/runs/'
