[CmdletBinding()]
param(
    [ValidateSet('VelocityToVelocity', 'VelocityToBungee', 'BungeeToVelocity', 'BungeeToBungee', 'All')]
    [string]$Pair = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$gradle = Join-Path $repoRoot 'gradlew.bat'
$tests = switch ($Pair) {
    'VelocityToVelocity' { @('com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.federationVelocityToVelocityRealProcessGate') }
    'VelocityToBungee' { @('com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.federationVelocityToBungeeRealProcessGate') }
    'BungeeToVelocity' { @('com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.federationBungeeToVelocityRealProcessGate') }
    'BungeeToBungee' { @('com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.federationBungeeToBungeeRealProcessGate') }
    default { @(
        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.federationVelocityToVelocityRealProcessGate',
        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.federationVelocityToBungeeRealProcessGate',
        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.federationBungeeToVelocityRealProcessGate',
        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.federationBungeeToBungeeRealProcessGate'
    ) }
}

foreach ($test in $tests) {
    Write-Host "MCAce federation proxy matrix: $test"
    & $gradle '-Dmcace.runtime.federation.enabled=true' ':mcace-runtime-integration:test' `
        '--tests' $test '--rerun-tasks' '--no-build-cache' '--no-daemon' '--console=plain'
    if ($LASTEXITCODE -ne 0) {
        throw "MCAce federation proxy matrix failed: $test"
    }
}

Write-Output 'FEDERATION_PROXY_MATRIX_PASS|build/runtime-federation-matrix/runs/'
