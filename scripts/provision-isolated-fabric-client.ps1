#requires -Version 7.0

[CmdletBinding()]
param(
    [string]$SourceClientRoot = 'E:\Ellan艾尔岚-客户端-26.2',
    [string]$TargetRoot = 'D:\MCAce-gui-client-26.2',
    [string]$ArtifactPath = 'C:\Projects\MCAce\build\release-bundle\mcace-client-fabric-26.2.jar',
    [switch]$KeepExistingTarget
)

$ErrorActionPreference = 'Stop'

function Assert-Directory([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Label directory is missing: $Path"
    }
}

function Assert-File([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label file is missing: $Path"
    }
}

function Copy-Tree([string]$Source, [string]$Destination, [string]$LogPath, [string[]]$ExcludedDirectories = @()) {
    Assert-Directory $Source 'copy source'
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    $args = @(
        $Source,
        $Destination,
        '/E',
        '/R:1',
        '/W:1',
        '/COPY:DAT',
        '/DCOPY:DAT',
        '/NFL',
        '/NDL',
        '/NJH',
        '/NJS',
        '/NP',
        "/LOG:$LogPath"
    )
    if ($ExcludedDirectories.Count -gt 0) {
        $args += '/XD'
        $args += $ExcludedDirectories
    }
    & robocopy @args | Out-Null
    $exitCode = $LASTEXITCODE
    if ($exitCode -gt 7) {
        throw "robocopy failed ($exitCode): $Source -> $Destination"
    }
    return $exitCode
}

Assert-Directory $SourceClientRoot 'source client'
Assert-File $ArtifactPath 'MCAce artifact'

$sourceMinecraft = Join-Path $SourceClientRoot '.minecraft'
$sourceVersion = Join-Path $sourceMinecraft 'versions\EllanTOP-26.2'
$sourceMods = Join-Path $sourceVersion 'mods'
$sourceLaunch = Join-Path $SourceClientRoot 'PCL\LatestLaunch.bat'
$sourceVersionJar = Join-Path $sourceVersion 'EllanTOP-26.2.jar'
$checksumsPath = Join-Path (Split-Path -Parent $ArtifactPath) 'SHA256SUMS'

Assert-Directory $sourceMinecraft 'source .minecraft'
Assert-Directory $sourceVersion 'source version'
Assert-Directory $sourceMods 'source mods'
Assert-File $sourceVersionJar 'source version jar'
Assert-File $sourceLaunch 'source launch recipe'
Assert-File $checksumsPath 'release checksums'

$artifactHash = (Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256).Hash.ToUpperInvariant()
$checksumLine = Get-Content -LiteralPath $checksumsPath | Where-Object {
    $_ -match [regex]::Escape((Split-Path -Leaf $ArtifactPath))
} | Select-Object -First 1
if ($null -eq $checksumLine -or $checksumLine -notmatch '^\s*([0-9A-Fa-f]{64})\s+[* ]?(.+)$') {
    throw "No parseable checksum entry for $(Split-Path -Leaf $ArtifactPath)"
}
$expectedHash = $Matches[1].ToUpperInvariant()
if ($expectedHash -cne $artifactHash) {
    throw "Artifact checksum mismatch: expected $expectedHash, observed $artifactHash"
}

$resolvedTargetRoot = [IO.Path]::GetFullPath($TargetRoot).TrimEnd('\')
$resolvedTargetParent = Split-Path -Parent $resolvedTargetRoot
if ($resolvedTargetRoot -notmatch '^D:\\MCAce-gui-client-26\.2$') {
    throw "Refusing an unexpected target path: $resolvedTargetRoot"
}
New-Item -ItemType Directory -Force -Path $resolvedTargetParent | Out-Null

$timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$backupPath = $null
if (Test-Path -LiteralPath $resolvedTargetRoot) {
    if (-not $KeepExistingTarget) {
        $backupPath = "$resolvedTargetRoot.backup-$timestamp"
        Move-Item -LiteralPath $resolvedTargetRoot -Destination $backupPath
    }
}
New-Item -ItemType Directory -Force -Path $resolvedTargetRoot | Out-Null

$targetMinecraft = Join-Path $resolvedTargetRoot '.minecraft'
$targetLibraries = Join-Path $targetMinecraft 'libraries'
$targetAssets = Join-Path $targetMinecraft 'assets'
$targetVersion = Join-Path $targetMinecraft 'versions\EllanTOP-26.2'
$targetMods = Join-Path $targetVersion 'mods'
$targetArtifact = Join-Path $targetMods (Split-Path -Leaf $ArtifactPath)
$copyLog = Join-Path $resolvedTargetRoot 'provision-robocopy.log'

$copyCodes = [ordered]@{}
$copyCodes.libraries = Copy-Tree (Join-Path $sourceMinecraft 'libraries') $targetLibraries $copyLog
$copyCodes.assets = Copy-Tree (Join-Path $sourceMinecraft 'assets') $targetAssets $copyLog
$copyCodes.version = Copy-Tree $sourceVersion $targetVersion $copyLog @(
    (Join-Path $sourceVersion 'logs'),
    (Join-Path $sourceVersion 'crash-reports'),
    (Join-Path $sourceVersion 'saves'),
    (Join-Path $sourceVersion 'screenshots'),
    (Join-Path $sourceVersion 'downloads'),
    (Join-Path $sourceVersion 'PCL')
)

New-Item -ItemType Directory -Force -Path $targetMods | Out-Null
Copy-Item -LiteralPath $ArtifactPath -Destination $targetArtifact -Force
$installedHash = (Get-FileHash -LiteralPath $targetArtifact -Algorithm SHA256).Hash.ToUpperInvariant()
if ($installedHash -cne $artifactHash) {
    throw "Installed artifact checksum mismatch: expected $artifactHash, observed $installedHash"
}

# PCL's recipe is used only as a classpath/runtime source. Its account arguments
# are rewritten to an offline test identity before the recipe is persisted.
$targetLaunch = Join-Path $resolvedTargetRoot 'launch-offline.bat'
$launchText = Get-Content -LiteralPath $sourceLaunch -Raw
$launchText = $launchText.Replace($SourceClientRoot, $resolvedTargetRoot)
$launchText = $launchText.Replace($sourceMinecraft, $targetMinecraft)
$launchText = $launchText.Replace($sourceVersion, $targetVersion)
$launchText = [regex]::Replace($launchText, '(?i)(--username\s+)(?:"[^"]*"|\S+)', '${1}MCAceGuiTest')
$launchText = [regex]::Replace($launchText, '(?i)(--uuid\s+)(?:"[^"]*"|\S+)', '${1}00000000-0000-0000-0000-000000000001')
$launchText = [regex]::Replace($launchText, '(?i)(--accessToken\s+)(?:"[^"]*"|\S+)', '${1}0')
$launchText = [regex]::Replace($launchText, '(?i)(--clientId\s+)(?:"[^"]*"|\S+)', '${1}0')
$launchText = [regex]::Replace($launchText, '(?i)(--xuid\s+)(?:"[^"]*"|\S+)', '${1}0')
$launchText = [regex]::Replace($launchText, '(?i)(--userProperties\s+)(?:"[^"]*"|\S+)', '${1}"{}"')
$launchText = [regex]::Replace($launchText, '(?i)--width\s+\d+\s+--height\s+\d+', '--width 1280 --height 720')
$launchText = $launchText -replace '(?im)^\s*pause\s*$', 'rem pause disabled for automated GUI smoke test'
if ($launchText -match [regex]::Escape($SourceClientRoot) -or
    $launchText -match '(?i)--accessToken\s+(?!0(?:\s|$))\S+' -or
    $launchText -match '(?i)--clientId\s+(?!0(?:\s|$))\S+' -or
    $launchText -match '(?i)--xuid\s+(?!0(?:\s|$))\S+') {
    throw 'Sanitized launch recipe still contains source paths or non-offline identity values'
}
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($targetLaunch, $launchText, $utf8NoBom)

$sourceModCount = (Get-ChildItem -LiteralPath $sourceMods -File -Filter '*.jar').Count
$targetModCount = (Get-ChildItem -LiteralPath $targetMods -File -Filter '*.jar').Count
$manifest = [ordered]@{
    schema = 'MCACE_ISOLATED_FABRIC_CLIENT_PROVISION_V1'
    generated_at = (Get-Date).ToUniversalTime().ToString('o')
    source_client_root = $SourceClientRoot
    target_root = $resolvedTargetRoot
    game_directory = $targetVersion
    minecraft_version = '26.2'
    loader = 'Fabric'
    artifact = [ordered]@{
        file = (Split-Path -Leaf $ArtifactPath)
        source_path = $ArtifactPath
        sha256 = $artifactHash
        size_bytes = (Get-Item -LiteralPath $ArtifactPath).Length
        installed_path = $targetArtifact
        installed_sha256 = $installedHash
    }
    source_mod_jar_count = $sourceModCount
    target_mod_jar_count = $targetModCount
    copy_exit_codes = $copyCodes
    excluded_directories = @('logs','crash-reports','saves','screenshots','downloads','PCL')
    authentication = 'offline-test-identity; no launcher profile or access token copied'
    launch_recipe = 'launch-offline.bat'
    rollback_backup = $backupPath
}
[IO.File]::WriteAllText(
    (Join-Path $resolvedTargetRoot 'provision-manifest.json'),
    ($manifest | ConvertTo-Json -Depth 8),
    $utf8NoBom
)

Write-Output 'MCACE_ISOLATED_CLIENT_PROVISION_PASS'
Write-Output ("target_root=" + $resolvedTargetRoot)
Write-Output ("game_directory=" + $targetVersion)
Write-Output ("artifact=" + (Split-Path -Leaf $ArtifactPath))
Write-Output ("artifact_sha256=" + $artifactHash)
Write-Output ("source_mod_jar_count=" + $sourceModCount)
Write-Output ("target_mod_jar_count=" + $targetModCount)
Write-Output ("launch_recipe=" + $targetLaunch)
if ($backupPath) {
    Write-Output ("rollback_backup=" + $backupPath)
}
