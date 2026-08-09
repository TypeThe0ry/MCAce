[CmdletBinding()]
param(
    [ValidateSet('Velocity', 'Bungee', 'Both')]
    [string]$Proxy = 'Both'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$gradle = Join-Path $repoRoot 'gradlew.bat'
$tests = switch ($Proxy) {
    'Velocity' { @('com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realVelocityModernForwardingOfflinePlayerProbeReachesMCAceChannel') }
    'Bungee' { @('com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realBungeeIpForwardingOfflinePlayerProbeReachesMCAceChannel') }
    default { @(
        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realVelocityModernForwardingOfflinePlayerProbeReachesMCAceChannel',
        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realBungeeIpForwardingOfflinePlayerProbeReachesMCAceChannel'
    ) }
}

foreach ($test in $tests) {
    Write-Host "MCAce proxy admission smoke: $test"
    & $gradle ':mcace-runtime-integration:test' '--tests' $test '--rerun-tasks' '--no-build-cache' '--no-daemon' '--console=plain'
    if ($LASTEXITCODE -ne 0) {
        throw "MCAce proxy admission smoke failed: $test"
    }
}

Write-Output 'PROXY_ADMISSION_PLAYER_SMOKE_PASS|build/runtime-player-probe/runs/'
