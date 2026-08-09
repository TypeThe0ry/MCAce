[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$tool = Join-Path $PSScriptRoot 'verify-catalog-provenance.ps1'

function Invoke-JsonTool([string[]]$ToolArguments) {
    $reportPath = Join-Path ([IO.Path]::GetTempPath()) ('mcace-catalog-provenance-' + [Guid]::NewGuid().ToString('N') + '.json')
    try {
        if ($ToolArguments.Count -eq 1 -and $ToolArguments[0] -eq '-SelfTest') {
            & $tool -SelfTest -ReportPath $reportPath
        } elseif ($ToolArguments.Count -eq 2 -and $ToolArguments[0] -eq '-CatalogPath') {
            & $tool -CatalogPath $ToolArguments[1] -ReportPath $reportPath
        } else {
            throw 'test harness does not permit arbitrary verifier arguments'
        }
        if ($LASTEXITCODE -ne 0) { throw 'catalog provenance tool failed' }
        return (Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json -ErrorAction Stop)
    } finally {
        Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue
    }
}

$selfTest = Invoke-JsonTool -ToolArguments @('-SelfTest')
if ($selfTest.status -ne 'passed' -or @($selfTest.tests | Where-Object { -not $_.passed }).Count -ne 0) { throw 'catalog provenance self-test did not pass' }
$starter = Invoke-JsonTool -ToolArguments @('-CatalogPath', (Join-Path $repoRoot 'examples\disposition-catalog.textproto'))
if ($starter.status -ne 'offline_valid' -or $starter.network_requested -or @($starter.entries).Count -ne 3) { throw 'starter catalog offline validation did not produce the expected bounded report' }
foreach ($entry in @($starter.entries)) {
    if ($entry.status -ne 'offline_valid' -or [string]::IsNullOrWhiteSpace($entry.selector_artifact_id) -or $entry.source.uri -match '\?' -or $entry.source.uri -notmatch '^https://raw\.githubusercontent\.com/') { throw 'starter catalog report exposed an invalid source or did not validate offline' }
}
[Console]::Out.WriteLine('{"schema":1,"tool":"mcace-catalog-provenance-review-tests","status":"passed"}')
