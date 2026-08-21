[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$target = Join-Path $PSScriptRoot 'proxy-admission-player-smoke.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $target, [ref]$tokens, [ref]$errors)
if (@($errors).Count -ne 0) {
    throw "PROXY_ADMISSION_WRAPPER_PARSE_FAILED: $($errors -join '; ')"
}
$source = Get-Content -LiteralPath $target -Raw
$required = [ordered]@{
    report_only = $source -match '\[switch\]\$ReportOnly'
    paper_pin = $source -match '39bd8c00b9e18de91dcabd3cc3dcfa5328685a53b7187a2f63280c22e2d287b9'
    direct_gradle = $source -match 'Resolve-OfflineGradle' -and $source -notmatch '& \$gradlew'
    offline = $source -match "'--offline'"
    no_cache = $source -match "'--no-build-cache'"
    no_configuration_cache = $source -match "'--no-configuration-cache'"
    no_daemon = $source -match "'--no-daemon'"
    no_parallel = $source -match "'--no-parallel'"
    one_worker = $source -match "'--max-workers=1'"
    source_binding = $source -match 'source_manifest_sha256'
    jar_binding = $source -match 'velocity_plugin_sha256' -and
        $source -match 'bungee_plugin_sha256' -and $source -match 'paper_plugin_sha256'
    raw_binding = $source -match 'raw_report_sha256'
    context_gate = $source -match 'backend_context_shadow_audit'
    cleanup_gate = $source -match 'remaining_run_processes'
    no_download = $source -notmatch 'Invoke-WebRequest|Invoke-RestMethod|HttpClient|WebClient|curl|wget'
}
$failed = @($required.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key)
if ($failed.Count -ne 0) {
    throw "PROXY_ADMISSION_WRAPPER_STATIC_FAILED: $($failed -join ', ')"
}
Write-Output 'PROXY_ADMISSION_WRAPPER_STATIC_PASS'
