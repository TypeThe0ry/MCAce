#requires -Version 7.0

[CmdletBinding()]
param(
    [string]$TargetRoot = 'D:\MCAce-gui-client-26.2',
    [string]$OutputPath = 'C:\Projects\MCAce\build\isolated-fabric-client-smoke\report.json'
)

$ErrorActionPreference = 'Stop'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

Assert-True (Test-Path -LiteralPath $TargetRoot -PathType Container) "isolated client root missing: $TargetRoot"
$manifestPath = Join-Path $TargetRoot 'provision-manifest.json'
$launchPath = Join-Path $TargetRoot 'launch-offline.bat'
Assert-True (Test-Path -LiteralPath $manifestPath -PathType Leaf) 'provision manifest missing'
Assert-True (Test-Path -LiteralPath $launchPath -PathType Leaf) 'offline launch recipe missing'

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
Assert-True ([string]$manifest.schema -ceq 'MCACE_ISOLATED_FABRIC_CLIENT_PROVISION_V1') 'provision manifest schema mismatch'
Assert-True ([string]$manifest.minecraft_version -ceq '26.2') 'isolated client Minecraft version mismatch'
Assert-True ([string]$manifest.loader -ceq 'Fabric') 'isolated client loader mismatch'

$gameDirectory = [string]$manifest.game_directory
$artifactPath = [string]$manifest.artifact.installed_path
$logPath = Join-Path $gameDirectory 'logs\latest.log'
Assert-True (Test-Path -LiteralPath $gameDirectory -PathType Container) 'isolated game directory missing'
Assert-True (Test-Path -LiteralPath $artifactPath -PathType Leaf) 'installed MCAce artifact missing'
Assert-True (Test-Path -LiteralPath $logPath -PathType Leaf) 'isolated Fabric latest.log missing'

$installedHash = Get-Sha256 $artifactPath
$manifestHash = ([string]$manifest.artifact.sha256).ToUpperInvariant()
Assert-True ($installedHash -ceq $manifestHash) "installed artifact hash mismatch: $installedHash != $manifestHash"

$logText = Get-Content -LiteralPath $logPath -Raw
$loadedModMarker = $logText -match '(?m)^\s*- mcace 0\.0\.1\s*$'
$artifactLoadedMarker = $logText -match 'MCACE_FABRIC_ARTIFACT_LOADED\s+version=0\.0\.1\s+build_id=fabric-26\.2-'
$initializedMarker = $logText -match 'MCAce Fabric client initialized'
$consentRendered = $logText -match 'MCAce enablement consent screen rendered'
$handshakeMarker = $logText -match '(?i)(SERVER_HELLO|CLIENT_HELLO|MCAce authentication|integrity bundle)'

$runtimeProcesses = @(Get-CimInstance Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -and $_.CommandLine -like "*$TargetRoot*"
})
$windowProcesses = @(Get-Process java,javaw -ErrorAction SilentlyContinue | Where-Object {
    $_.MainWindowTitle -and $_.MainWindowTitle -match '(?i)(Minecraft|MCAce|Ellan)' -and
        ($runtimeProcesses.ProcessId -contains $_.Id)
})

$sourceCommit = ''
try { $sourceCommit = (& git -C 'C:\Projects\MCAce' rev-parse HEAD).Trim() } catch { $sourceCommit = 'unavailable' }
$reportDirectory = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Force -Path $reportDirectory | Out-Null

$report = [ordered]@{
    schema = 'MCACE_ISOLATED_FABRIC_CLIENT_GUI_SMOKE_V1'
    generated_at = (Get-Date).ToUniversalTime().ToString('o')
    source_commit = $sourceCommit
    target_root = $TargetRoot
    game_directory = $gameDirectory
    minecraft_version = [string]$manifest.minecraft_version
    loader = [string]$manifest.loader
    artifact = [ordered]@{
        file = [string]$manifest.artifact.file
        sha256 = $installedHash
        size_bytes = [long]$manifest.artifact.size_bytes
        installed_path = $artifactPath
    }
    mod_counts = [ordered]@{
        source_mod_jar_count = [int]$manifest.source_mod_jar_count
        target_mod_jar_count = [int]$manifest.target_mod_jar_count
        mcace_jar_present = $true
    }
    process = [ordered]@{
        java_process_count = $runtimeProcesses.Count
        visible_window_count = $windowProcesses.Count
        visible_window_titles = @($windowProcesses | ForEach-Object { $_.MainWindowTitle })
        responding = (@($windowProcesses | Where-Object { $_.Responding }).Count -gt 0)
    }
    observations = [ordered]@{
        fabric_modlist_contains_mcace = $loadedModMarker
        exact_artifact_loaded_marker = $artifactLoadedMarker
        client_initialized = $initializedMarker
        visible_enablement_consent_rendered = $consentRendered
        server_handshake_observed = $handshakeMarker
        latest_log = $logPath
    }
    gui_control = [ordered]@{
        requested = 'Computer Use'
        callable_surface = 'not_exposed_in_current_thread'
        fallback = 'direct_process_launch_and_log_observation'
        screenshot_captured = $false
        human_enablement_click = $false
    }
    pass = ($installedHash -ceq $manifestHash -and $loadedModMarker -and
        $artifactLoadedMarker -and $initializedMarker -and $runtimeProcesses.Count -gt 0)
    limitations = @(
        'This report proves isolated Fabric client startup and exact MCAce mod loading.',
        'No server key pin or server connection was configured in the offline smoke.',
        'Therefore no visible Enable MCAce decision, client modlist upload, or SERVER_CONFIRMED event is claimed.',
        'Computer Use control/screenshot evidence requires the callable node_repl/@oai/sky surface to be exposed.'
    )
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($OutputPath, ($report | ConvertTo-Json -Depth 10), $utf8NoBom)

if (-not $report.pass) {
    throw "MCACE_ISOLATED_CLIENT_GUI_PROCESS_SMOKE_FAIL: $OutputPath"
}
Write-Output 'MCACE_ISOLATED_CLIENT_GUI_PROCESS_SMOKE_PASS'
Write-Output ("report=" + $OutputPath)
Write-Output ("artifact_sha256=" + $installedHash)
Write-Output ("java_process_count=" + $runtimeProcesses.Count)
Write-Output ("visible_window_count=" + $windowProcesses.Count)
Write-Output ("consent_rendered=" + $consentRendered)
Write-Output ("server_handshake_observed=" + $handshakeMarker)
