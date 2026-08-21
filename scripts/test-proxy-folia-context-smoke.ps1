[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$target = Join-Path $PSScriptRoot 'proxy-folia-context-smoke.ps1'
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($target, [ref]$tokens, [ref]$errors) | Out-Null
if (@($errors).Count -ne 0) { throw "FOLIA_CONTEXT_WRAPPER_PARSE_FAILED: $($errors -join '; ')" }
$source = Get-Content -LiteralPath $target -Raw
$required = [ordered]@{
    explicit_prepared = $source -match '\[switch\]\$UsePreparedOffline'
    explicit_paths = $source -match '\$PreparedRoot' -and $source -match '\$FoliaJar'
    pinned_sha = $source -match 'dcf2333211c1468c8eddc482bc8549600818cc661a709124a79c752f8fa2ac3a'
    report_only = $source -match '\[switch\]\$ReportOnly'
    no_online_prepare = $source -notmatch 'folia-process-smoke|Invoke-WebRequest|Invoke-RestMethod|curl|wget'
    direct_gradle = $source -match 'Resolve-OfflineGradle'
    offline_flags = $source -match "'--offline'" -and $source -match "'--no-build-cache'" -and
        $source -match "'--no-configuration-cache'" -and $source -match "'--no-daemon'" -and
        $source -match "'--no-parallel'" -and $source -match "'--max-workers=1'"
    source_binding = $source -match 'source_manifest_sha256'
    jar_binding = $source -match 'velocity_plugin_sha256' -and
        $source -match 'bungee_plugin_sha256' -and $source -match 'paper_plugin_sha256'
    shadow_gate = $source -match 'backend_context_shadow_audit'
    honest_version = $source -match 'exact_folia_1_21_1_coverage = \$false'
}
$failed = @($required.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key)
if ($failed.Count -ne 0) { throw "FOLIA_CONTEXT_WRAPPER_STATIC_FAILED: $($failed -join ', ')" }
Write-Output 'FOLIA_CONTEXT_WRAPPER_STATIC_PASS'
