[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$target = Join-Path $PSScriptRoot 'platform-load-smoke.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($target, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'Smoke script parse failed' }
foreach ($name in @('Get-SmokeOfflinePlayerUuid', 'Get-SmokeInventoryReceipt', 'Wait-SmokeInventoryReceipt')) {
    $function = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if ($null -eq $function) { throw "Missing function $name" }
    . ([scriptblock]::Create($function.Extent.Text))
}
function Assert-True([bool]$Condition) { if (-not $Condition) { throw 'Inventory receipt assertion failed' } }
function Assert-Rejected([scriptblock]$Action) {
    $failed = $false
    try { & $Action | Out-Null } catch { $failed = $true }
    Assert-True $failed
}
Assert-True ((Get-SmokeOfflinePlayerUuid 'Notch') -eq 'b50ad385-829d-3141-a216-7e7d7539ba7f')
Assert-True ((Get-SmokeOfflinePlayerUuid 'notch') -ne (Get-SmokeOfflinePlayerUuid 'Notch'))
Assert-Rejected { Get-SmokeOfflinePlayerUuid "name`nstop" }
$line = '[18:00:00 INFO]: MCAce: inventory state=FRESH updateSequence=0 loadedMods=17 selectedResourcePacks=2 selectedShaderPacks=0 receivedAt=2026-09-08T10:00:00Z (client claims; not cheat-free proof or an execution receipt)'
$receipt = Get-SmokeInventoryReceipt $line
Assert-True ($receipt.loaded_mods -eq 17 -and $receipt.selected_resource_packs -eq 2)
Assert-True (-not $receipt.release_evidence -and -not $receipt.full_modlist_verified -and -not $receipt.xray_detection_verified)
Assert-True ($null -eq (Get-SmokeInventoryReceipt 'MCAce verified'))
Assert-True ($null -eq (Get-SmokeInventoryReceipt 'MCAce: inventory state=UNAVAILABLE'))
Assert-True ($null -eq (Get-SmokeInventoryReceipt $line.Replace('state=FRESH', 'state=STALE')))
Assert-True ($null -eq (Get-SmokeInventoryReceipt $line.Replace('state=FRESH', 'state=CLOCK_ANOMALY')))
Assert-True ($null -eq (Get-SmokeInventoryReceipt $line.Replace('loadedMods=17', 'loadedMods=-1')))
Assert-Rejected { Get-SmokeInventoryReceipt $line.Replace('loadedMods=17', 'loadedMods=0') }
Assert-Rejected { Get-SmokeInventoryReceipt $line.Replace('loadedMods=17', 'loadedMods=99999') }
Assert-Rejected { Get-SmokeInventoryReceipt $line.Replace('2026-09-08T10:00:00Z', 'invalid') }
Assert-Rejected { Get-SmokeInventoryReceipt "$line`n$line" }
$log = New-TemporaryFile
try {
    $writer = [pscustomobject]@{ Path = $log.FullName; Response = ''; Replace = $false; Command = '' }
    $writer | Add-Member ScriptMethod WriteLine {
        param($command)
        $this.Command = $command
        if ($this.Replace) { [IO.File]::WriteAllText($this.Path, $this.Response) }
        else { [IO.File]::AppendAllText($this.Path, $this.Response) }
    }
    $writer | Add-Member ScriptMethod Flush { }
    $service = [pscustomobject]@{ Process = [pscustomobject]@{ HasExited = $false; StandardInput = $writer } }
    [IO.File]::WriteAllText($log.FullName, "$line`n")
    $writer.Response = $line.Replace('loadedMods=17', 'loadedMods=23') + "`n"
    $fresh = Wait-SmokeInventoryReceipt $service $log.FullName 'Notch'
    Assert-True ($fresh.loaded_mods -eq 23)
    Assert-True ($writer.Command -eq 'mcaceobservation inventory b50ad385-829d-3141-a216-7e7d7539ba7f')
    $writer.Replace = $true
    $writer.Response = "rotated`n$line`n"
    Assert-Rejected { Wait-SmokeInventoryReceipt $service $log.FullName 'Notch' }
    $service.Process.HasExited = $true
    Assert-Rejected { Wait-SmokeInventoryReceipt $service $log.FullName 'Notch' }
} finally {
    Remove-Item -LiteralPath $log.FullName -Force
}
Write-Output 'SMOKE_INVENTORY_RECEIPT_PARSER_PASS|runtime_gui=false'
