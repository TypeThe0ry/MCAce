[CmdletBinding()]
param(
    [switch]$WithFabricClient,
    [switch]$WithFabricEvidence,
    [ValidatePattern('^[A-Za-z0-9_]{3,16}$')]
    [string]$FabricEvidencePlayerName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($WithFabricEvidence) {
    $WithFabricClient = $true
    if ([string]::IsNullOrWhiteSpace($FabricEvidencePlayerName)) {
        throw '-WithFabricEvidence requires -FabricEvidencePlayerName matching the local Fabric development profile.'
    }
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$smokeRoot = Join-Path $repoRoot 'build\platform-smoke'
$cacheRoot = Join-Path $smokeRoot 'cache'
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
$runRoot = Join-Path $smokeRoot (Join-Path 'runs' $runId)
$velocityRoot = Join-Path $runRoot 'velocity'
$paperRoot = Join-Path $runRoot 'paper'
$preparedPaperRoot = Join-Path $cacheRoot 'paper-1.21.1-133-prepared'
$userAgent = 'MCAce-platform-smoke/0.1 (https://github.com/EllanServer/MCAce)'

$velocityArtifact = @{
    Name = 'velocity-3.5.1-615.jar'
    Url = 'https://fill-data.papermc.io/v1/objects/b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3/velocity-3.5.1-615.jar'
    Sha256 = 'b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3'
}
$paperArtifact = @{
    Name = 'paper-1.21.1-133.jar'
    Url = 'https://fill-data.papermc.io/v1/objects/39bd8c00b9e18de91dcabd3cc3dcfa5328685a53b7187a2f63280c22e2d287b9/paper-1.21.1-133.jar'
    Sha256 = '39bd8c00b9e18de91dcabd3cc3dcfa5328685a53b7187a2f63280c22e2d287b9'
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-VerifiedArtifact([hashtable]$Artifact) {
    $urlMatch = [regex]::Match($Artifact.Url, '^https://fill-data\.papermc\.io/v1/objects/(?<urlHash>[0-9a-f]{64})/[^/]+$')
    if ((-not $urlMatch.Success) -or ($Artifact.Sha256 -notmatch '^[0-9a-f]{64}$') -or
            ($urlMatch.Groups['urlHash'].Value -ne $Artifact.Sha256)) {
        throw "Artifact source or SHA-256 declaration is not a fixed official PaperMC value: $($Artifact.Name)"
    }
    $path = Join-Path $cacheRoot $Artifact.Name
    if ((Test-Path -LiteralPath $path) -and
            ((Get-Item -LiteralPath $path).PSIsContainer -or
             (Get-Sha256 $path) -ne $Artifact.Sha256)) {
        $quarantine = "$path.invalid-$runId"
        Move-Item -LiteralPath $path -Destination $quarantine
        Write-Warning "Quarantined an artifact with an unexpected hash at $quarantine"
    }
    if (-not (Test-Path -LiteralPath $path)) {
        $download = "$path.download-$runId"
        try {
            Invoke-WebRequest -Headers @{ 'User-Agent' = $userAgent } -Uri $Artifact.Url -OutFile $download
            if ((Get-Sha256 $download) -ne $Artifact.Sha256) {
                throw "Downloaded artifact failed SHA-256 verification: $($Artifact.Name)"
            }
            Move-Item -LiteralPath $download -Destination $path
        } finally {
            if (Test-Path -LiteralPath $download) {
                Remove-Item -LiteralPath $download -Force
            }
        }
    }
    if ((Get-Sha256 $path) -ne $Artifact.Sha256) {
        throw "Cached artifact failed SHA-256 verification: $($Artifact.Name)"
    }
    return $path
}

function Get-FreeLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

function Test-LoopbackPortFree([int]$Port) {
    return -not @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -eq $Port -and $_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::') }).Count
}

function Assert-LoopbackListener($Service, [int]$Port) {
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop |
        Where-Object { $_.LocalAddress -in @('127.0.0.1', '::1') })
    if ($listeners.Count -eq 0) {
        throw "$($Service.Name) did not expose the expected loopback listener on port $Port"
    }
    if (@(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop |
            Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') }).Count -ne 0) {
        throw "$($Service.Name) exposed a non-loopback listener on port $Port"
    }
    if (-not @($listeners | Where-Object { $_.OwningProcess -eq $Service.Pid }).Count) {
        throw "$($Service.Name) loopback listener on port $Port is not owned by its smoke process"
    }
    return [int]$listeners[0].OwningProcess
}

function Get-SmokeJava {
    $candidates = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($env:JAVA_HOME)) {
        $candidates.Add((Join-Path $env:JAVA_HOME 'bin\java.exe'))
    }
    foreach ($path in @(Get-ChildItem 'C:\Program Files\Java\jdk*\bin\java.exe' -File -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName)) {
        $candidates.Add($path)
    }
    foreach ($command in @(Get-Command java.exe -All -ErrorAction SilentlyContinue)) {
        $candidates.Add($command.Source)
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $fallback = $null
    foreach ($candidate in $candidates) {
        if (([string]::IsNullOrWhiteSpace($candidate)) -or (-not (Test-Path -LiteralPath $candidate)) -or
                (-not $seen.Add($candidate))) { continue }
        $versionText = (& $candidate -version 2>&1 | Out-String)
        $match = [regex]::Match($versionText, 'version "(?<major>\d+)')
        if (-not $match.Success) { continue }
        $major = [int]$match.Groups['major'].Value
        if ($major -eq 21) { return $candidate }
        if ($major -ge 21 -and $null -eq $fallback) { $fallback = $candidate }
    }
    if ($null -ne $fallback) { return $fallback }
    throw 'A Java 21+ executable is required for the real platform smoke'
}

function Expand-VelocityConfiguration([string]$Jar, [string]$Destination, [int]$ProxyPort, [int]$PaperPort) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Jar)
    try {
        $entry = $archive.GetEntry('default-velocity.toml')
        if ($null -eq $entry) {
            throw 'Velocity artifact does not contain default-velocity.toml'
        }
        $reader = [System.IO.StreamReader]::new($entry.Open(), [System.Text.Encoding]::UTF8)
        try {
            $configuration = $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
    } finally {
        $archive.Dispose()
    }
    $configuration = $configuration.Replace('bind = "0.0.0.0:25565"', "bind = `"127.0.0.1:$ProxyPort`"")
    $configuration = $configuration.Replace('online-mode = true', 'online-mode = false')
    $configuration = $configuration.Replace('force-key-authentication = true', 'force-key-authentication = false')
    $configuration = $configuration.Replace('lobby = "127.0.0.1:30066"', "lobby = `"127.0.0.1:$PaperPort`"")
    [System.IO.File]::WriteAllText($Destination, $configuration, [System.Text.UTF8Encoding]::new($false))
}

function Test-JarEntry([string]$Jar, [string]$EntryName) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Jar)
    try { return $null -ne $archive.GetEntry($EntryName) }
    finally { $archive.Dispose() }
}

function Start-JavaService(
        [string]$Name,
        [string]$WorkingDirectory,
        [string]$Jar,
        [string]$MaximumHeap,
        [string[]]$ExtraArguments) {
    $java = $script:SmokeJavaPath
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $java
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    [void]$startInfo.ArgumentList.Add('-Xms128m')
    [void]$startInfo.ArgumentList.Add("-Xmx$MaximumHeap")
    [void]$startInfo.ArgumentList.Add('-jar')
    [void]$startInfo.ArgumentList.Add($Jar)
    foreach ($argument in $ExtraArguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Could not start $Name"
    }
    return [pscustomobject]@{
        Name = $Name
        Process = $process
        Pid = $process.Id
        WorkingDirectory = $WorkingDirectory
        Stdout = $process.StandardOutput.ReadToEndAsync()
        Stderr = $process.StandardError.ReadToEndAsync()
        ConsolePath = Join-Path $WorkingDirectory "$Name-console.log"
    }
}

function Start-FabricClient([string]$RunDirectory, [string]$ServerAddress, [bool]$AwaitEvidence) {
    $java = $script:SmokeJavaPath
    $wrapperJar = Join-Path $repoRoot 'gradle\wrapper\gradle-wrapper.jar'
    $fabricProjectDirectory = Join-Path $repoRoot 'mcace-client-fabric'
    $loomRunDirectory = [System.IO.Path]::GetRelativePath($fabricProjectDirectory, $RunDirectory)
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $java
    $startInfo.WorkingDirectory = $repoRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $arguments = [System.Collections.Generic.List[string]]::new()
    foreach ($argument in @(
            '-Xms128m',
            '-Xmx1024m',
            '-classpath',
            $wrapperJar,
            'org.gradle.wrapper.GradleWrapperMain',
            ':mcace-client-fabric:runClient',
            "-PmcaceSmokeRunDirectory=$loomRunDirectory",
            "-PmcaceSmokeServerAddress=$ServerAddress",
            '--no-configuration-cache',
            '--no-daemon')) {
        $arguments.Add($argument)
    }
    if ($AwaitEvidence) {
        $arguments.Add('-PmcaceSmokeEvidence=true')
    }
    foreach ($argument in $arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'Could not start the Fabric development client'
    }
    return [pscustomobject]@{
        Name = 'fabric-client'
        Process = $process
        Pid = $process.Id
        WorkingDirectory = $RunDirectory
        Stdout = $process.StandardOutput.ReadToEndAsync()
        Stderr = $process.StandardError.ReadToEndAsync()
        ConsolePath = Join-Path $RunDirectory 'fabric-client-console.log'
    }
}

function Stop-SmokeProcessTree([int]$RootPid, [string]$CommandMarker) {
    $snapshot = @(Get-CimInstance Win32_Process -ErrorAction Stop |
        Where-Object { $_.Name -eq 'java.exe' -and $_.CommandLine -like "*$CommandMarker*" })
    $pending = [System.Collections.Generic.Queue[int]]::new()
    $pending.Enqueue($RootPid)
    $descendants = [System.Collections.Generic.List[int]]::new()
    while ($pending.Count -gt 0) {
        $parentPid = $pending.Dequeue()
        foreach ($child in $snapshot | Where-Object { $_.ParentProcessId -eq $parentPid }) {
            if (-not $descendants.Contains([int]$child.ProcessId)) {
                $descendants.Add([int]$child.ProcessId)
                $pending.Enqueue([int]$child.ProcessId)
            }
        }
    }
    foreach ($pid in $descendants | Sort-Object -Descending) {
        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    }
}

function Stop-JavaService($Service, [string]$Command) {
    if ($null -eq $Service) {
        return
    }
    $process = $Service.Process
    $rootPid = $Service.Pid
    if (-not $process.HasExited) {
        if (-not [string]::IsNullOrEmpty($Command)) {
            try {
                $process.StandardInput.WriteLine($Command)
                $process.StandardInput.Flush()
            } catch {
                Write-Warning "Could not send graceful shutdown to $($Service.Name): $($_.Exception.Message)"
            }
        }
        if (-not $process.WaitForExit(30000)) {
            $process.Kill($true)
            [void]$process.WaitForExit(10000)
            Write-Warning "Forcibly stopped $($Service.Name) after graceful shutdown timeout"
        }
    }
    Stop-SmokeProcessTree $rootPid $Service.WorkingDirectory
    $stdout = if ($null -eq $Service.Stdout) { '' } else { $Service.Stdout.GetAwaiter().GetResult() }
    $stderr = if ($null -eq $Service.Stderr) { '' } else { $Service.Stderr.GetAwaiter().GetResult() }
    [System.IO.File]::WriteAllText(
        $Service.ConsolePath,
        $stdout + [Environment]::NewLine + $stderr,
        [System.Text.UTF8Encoding]::new($false))
    $process.Dispose()
}

function Wait-ServiceLog($Service, [string]$LogPath, [string[]]$RequiredText, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $LogPath) {
            $content = Get-Content -Raw -LiteralPath $LogPath -ErrorAction SilentlyContinue
            if ($null -eq $content) {
                $content = ''
            }
            $allPresent = $true
            foreach ($text in $RequiredText) {
                if (-not $content.Contains($text, [StringComparison]::Ordinal)) {
                    $allPresent = $false
                    break
                }
            }
            if ($allPresent) {
                return
            }
        }
        if ($Service.Process.HasExited) {
            throw "$($Service.Name) exited before its readiness markers were observed"
        }
        Start-Sleep -Seconds 1
    }
    throw "$($Service.Name) did not emit all readiness markers within $TimeoutSeconds seconds"
}

$script:SmokeJavaPath = Get-SmokeJava
New-Item -ItemType Directory -Force -Path $cacheRoot, $velocityRoot, $paperRoot | Out-Null
$velocityServerJar = Get-VerifiedArtifact $velocityArtifact
$paperServerJar = Get-VerifiedArtifact $paperArtifact

& (Join-Path $repoRoot 'gradlew.bat') :mcace-server-velocity:shadowJar :mcace-server-paper:shadowJar --no-daemon
if ($LASTEXITCODE -ne 0) {
    throw 'MCAce platform artifacts did not build successfully'
}

$velocityPlugin = Join-Path $repoRoot 'mcace-server-velocity\build\libs\mcace-server-velocity-0.1.0-SNAPSHOT.jar'
$paperPlugin = Join-Path $repoRoot 'mcace-server-paper\build\libs\mcace-server-paper-0.1.0-SNAPSHOT.jar'
if (-not (Test-Path -LiteralPath $velocityPlugin) -or -not (Test-Path -LiteralPath $paperPlugin)) {
    throw 'Expected MCAce platform artifacts were not produced'
}
$velocityTransportClassesPresent = Test-JarEntry $velocityPlugin 'com/ellan/mcace/velocity/MCAceVelocityChannels.class'
if (-not $velocityTransportClassesPresent) {
    throw 'Velocity MCAce plugin artifact is missing its client transport channel implementation'
}

$proxyPort = Get-FreeLoopbackPort
$paperPort = Get-FreeLoopbackPort
while ($paperPort -eq $proxyPort) {
    $paperPort = Get-FreeLoopbackPort
}

$velocityPlugins = Join-Path $velocityRoot 'plugins'
$paperPlugins = Join-Path $paperRoot 'plugins'
New-Item -ItemType Directory -Force -Path $velocityPlugins, $paperPlugins | Out-Null
Copy-Item -LiteralPath $velocityPlugin -Destination (Join-Path $velocityPlugins 'mcace.jar')
Copy-Item -LiteralPath $paperPlugin -Destination (Join-Path $paperPlugins 'mcace.jar')
Copy-Item -LiteralPath $velocityServerJar -Destination (Join-Path $velocityRoot 'velocity.jar')
Copy-Item -LiteralPath $paperServerJar -Destination (Join-Path $paperRoot 'paper.jar')
if (Test-Path -LiteralPath $preparedPaperRoot) {
    foreach ($directory in @('cache', 'libraries', 'versions')) {
        $preparedDirectory = Join-Path $preparedPaperRoot $directory
        if (Test-Path -LiteralPath $preparedDirectory) {
            Copy-Item -LiteralPath $preparedDirectory -Destination $paperRoot -Recurse
        }
    }
}
Expand-VelocityConfiguration (Join-Path $velocityRoot 'velocity.jar') (Join-Path $velocityRoot 'velocity.toml') `
        $proxyPort $paperPort
[System.IO.File]::WriteAllText(
    (Join-Path $paperRoot 'eula.txt'),
    "eula=true`n",
    [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText(
    (Join-Path $paperRoot 'server.properties'),
    "online-mode=false`nserver-ip=127.0.0.1`nserver-port=$paperPort`nenable-query=false`nmotd=MCAce platform smoke`n",
    [System.Text.UTF8Encoding]::new($false))

$velocity = $null
$paper = $null
$fabricClient = $null
$paperPin = $null
$paperPinBackup = $null
$passed = $false
$smokeFailure = $null
$report = $null
$reportPath = $null
$cleanupCompleted = $false
$velocityListenerPid = $null
$paperListenerPid = $null
$paperAdmissionChannelEnabled = $false
$noPlayerStartupPath = $false
$identityFingerprintBeforeRestart = $null
$identityFingerprintAfterRestart = $null
try {
    $velocity = Start-JavaService 'velocity' $velocityRoot (Join-Path $velocityRoot 'velocity.jar') '384m' @()
    $velocityLog = Join-Path $velocityRoot 'logs\latest.log'
    Wait-ServiceLog $velocity $velocityLog @(
        'MCAce Phase 2 handshake initialized',
        "Listening on /127.0.0.1:$proxyPort"
    ) 120
    $velocityListenerPid = Assert-LoopbackListener $velocity $proxyPort

    $velocityPin = Join-Path $velocityRoot 'plugins\mcace\identity\server-public-key.txt'
    if (-not (Test-Path -LiteralPath $velocityPin)) {
        throw 'Velocity did not create the MCAce server public-key pin'
    }
    $velocityPinBytes = [Convert]::FromBase64String((Get-Content -Raw -LiteralPath $velocityPin).Trim())
    if ($velocityPinBytes.Length -lt 32) {
        throw 'Velocity identity pin is not a valid Ed25519 public-key encoding'
    }
    $identityFingerprintBeforeRestart = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($velocityPinBytes)).ToLowerInvariant()
    Stop-JavaService $velocity 'end'
    $velocity = $null
    if (Test-Path -LiteralPath $velocityLog) { Remove-Item -LiteralPath $velocityLog -Force }
    $velocity = Start-JavaService 'velocity-restart' $velocityRoot (Join-Path $velocityRoot 'velocity.jar') '384m' @()
    Wait-ServiceLog $velocity $velocityLog @(
        'MCAce Phase 2 handshake initialized',
        "Listening on /127.0.0.1:$proxyPort"
    ) 120
    $velocityListenerPid = Assert-LoopbackListener $velocity $proxyPort
    $restartPinBytes = [Convert]::FromBase64String((Get-Content -Raw -LiteralPath $velocityPin).Trim())
    $identityFingerprintAfterRestart = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($restartPinBytes)).ToLowerInvariant()
    if ($identityFingerprintBeforeRestart -ne $identityFingerprintAfterRestart) {
        throw 'Velocity MCAce Ed25519 identity changed across a clean restart'
    }
    $paperData = Join-Path $paperRoot 'plugins\MCAce'
    New-Item -ItemType Directory -Force -Path $paperData | Out-Null
    $paperPin = Join-Path $paperData 'proxy-public-key.txt'
    Copy-Item -LiteralPath $velocityPin -Destination $paperPin

    $paper = Start-JavaService 'paper' $paperRoot (Join-Path $paperRoot 'paper.jar') '1024m' @('--nogui')
    $paperLog = Join-Path $paperRoot 'logs\latest.log'
    Wait-ServiceLog $paper $paperLog @(
        "Starting Minecraft server on 127.0.0.1:$paperPort",
        'MCAce signed proxy admission channel enabled',
        'Done ('
    ) 300
    $paperListenerPid = Assert-LoopbackListener $paper $paperPort
    if (-not (Test-Path -LiteralPath $preparedPaperRoot)) {
        New-Item -ItemType Directory -Path $preparedPaperRoot | Out-Null
        foreach ($directory in @('cache', 'libraries', 'versions')) {
            $runtimeDirectory = Join-Path $paperRoot $directory
            if (Test-Path -LiteralPath $runtimeDirectory) {
                Copy-Item -LiteralPath $runtimeDirectory -Destination $preparedPaperRoot -Recurse
            }
        }
    }

    $pinBytes = [Convert]::FromBase64String((Get-Content -Raw -LiteralPath $velocityPin).Trim())
    $pinFingerprint = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($pinBytes)).ToLowerInvariant()
    $paperLogText = Get-Content -Raw -LiteralPath $paperLog
    $paperAdmissionChannelEnabled = $paperLogText.Contains(
        'MCAce signed proxy admission channel enabled', [StringComparison]::Ordinal)
    $noPlayerStartupPath = -not $WithFabricClient
    if (-not $paperLogText.Contains($pinFingerprint, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Paper did not report the same pinned Velocity identity fingerprint'
    }
    $fabricReport = [ordered]@{
        outcome = 'SKIPPED'
        reason = 'WithFabricClient was not requested; no user Minecraft process was inspected or controlled.'
    }
    if ($WithFabricClient) {
        $fabricRoot = Join-Path $runRoot 'fabric-client'
        $fabricPinDirectory = Join-Path $fabricRoot 'config\mcace'
        New-Item -ItemType Directory -Force -Path $fabricPinDirectory, (Join-Path $fabricRoot 'mods') | Out-Null
        $serverAddress = "127.0.0.1:$proxyPort"
        $escapedPropertyAddress = $serverAddress.Replace(':', '\:')
        $pinValue = (Get-Content -Raw -LiteralPath $velocityPin).Trim()
        [System.IO.File]::WriteAllText(
            (Join-Path $fabricPinDirectory 'server-keys.properties'),
            "$escapedPropertyAddress=$pinValue`n",
            [System.Text.UTF8Encoding]::new($false))
        $fabricClient = Start-FabricClient $fabricRoot $serverAddress $WithFabricEvidence
        $fabricLog = Join-Path $fabricRoot 'logs\latest.log'
        Wait-ServiceLog $fabricClient $fabricLog @(
            'MCAce Fabric client initialized',
            'MCAce session verified at trust level VERIFIED with risk score 0'
        ) 300
        Wait-ServiceLog $paper $paperLog @(
            'Accepted signed MCAce admission state',
            'admission=VERIFIED, trust=VERIFIED, risk=0'
        ) 30
        Wait-ServiceLog $velocity $velocityLog @('MCAce verified') 30
        $evidenceReport = [ordered]@{
            outcome = 'NOT_REQUESTED'
            reason = 'WithFabricEvidence was not requested.'
        }
        if ($WithFabricEvidence) {
            Wait-ServiceLog $fabricClient $fabricLog @(
                'MCAce platform evidence smoke verified; waiting for a signed GAME_RENDER_FRAME request'
            ) 30
            # The console request is intentionally the only automated action. Consent remains a
            # visible, per-request human decision; this script has no cursor, window, desktop, or
            # operating-system screen-capture API.
            Write-Host 'MCAce evidence smoke: approve Allow once in the visible Fabric client window.'
            $velocity.Process.StandardInput.WriteLine(
                "mcaceevidence request $FabricEvidencePlayerName frame platform-smoke-frame")
            $velocity.Process.StandardInput.Flush()
            Wait-ServiceLog $fabricClient $fabricLog @(
                'MCAce evidence consent screen shown for signed GAME_RENDER_FRAME request',
                'MCAce evidence transfer COMPLETE request='
            ) 180
            $evidenceAudit = Join-Path $velocityRoot 'plugins\mcace\evidence-audit.log'
            $auditDeadline = [DateTime]::UtcNow.AddSeconds(30)
            $auditLine = $null
            while ([DateTime]::UtcNow -lt $auditDeadline) {
                if (Test-Path -LiteralPath $evidenceAudit) {
                    $auditLine = Get-Content -LiteralPath $evidenceAudit -ErrorAction SilentlyContinue |
                        Where-Object { $_ -match '^COLLECT status=EVIDENCE_COLLECTION_COLLECTED ' -and
                            $_ -match 'caseId=platform-smoke-frame ' -and
                            $_ -match 'scope=GAME_RENDER_FRAME ' -and $_ -match 'size=[1-9][0-9]* ' } |
                        Select-Object -Last 1
                    if ($null -ne $auditLine) { break }
                }
                Start-Sleep -Seconds 1
            }
            if ($null -eq $auditLine) {
                throw 'Velocity did not write a content-free COMPLETE audit summary for the signed game-render-frame request'
            }
            $evidenceAuditCopy = Join-Path $runRoot 'velocity-evidence-audit.log'
            Copy-Item -LiteralPath $evidenceAudit -Destination $evidenceAuditCopy
            $evidenceReport = [ordered]@{
                outcome = 'COMPLETE'
                request_scope = 'GAME_RENDER_FRAME'
                consent = 'manual-visible-allow-once'
                audit_log = $evidenceAuditCopy
                audit_summary = $auditLine
                raw_content_retained = $false
            }
        }
        if (-not $fabricClient.Process.WaitForExit(60000)) {
            $reason = if ($WithFabricEvidence) { 'evidence COMPLETE' } else { 'authentication result' }
            throw "Fabric client did not exit after $reason"
        }
        Stop-JavaService $fabricClient ''
        $fabricClient = $null
        $fabricEvidenceLog = Join-Path $runRoot 'fabric-client.log'
        Copy-Item -LiteralPath $fabricLog -Destination $fabricEvidenceLog
        $fabricReport = [ordered]@{
            minecraft_version = '1.21.1'
            loader_version = '0.19.3'
            server_address = $serverAddress
            log = $fabricEvidenceLog
            outcome = 'VERIFIED'
            risk_score = 0
            evidence = $evidenceReport
        }
    }
    $positivePaperLog = Join-Path $runRoot 'paper-positive.log'
    Copy-Item -LiteralPath $paperLog -Destination $positivePaperLog

    Stop-JavaService $paper 'stop'
    $paper = $null
    if (Test-Path -LiteralPath $paperLog) { Remove-Item -LiteralPath $paperLog -Force }
    $paperPinBackup = "$paperPin.intentionally-absent"
    Move-Item -LiteralPath $paperPin -Destination $paperPinBackup
    $paper = Start-JavaService 'paper-negative' $paperRoot (Join-Path $paperRoot 'paper.jar') '1024m' @('--nogui')
    Wait-ServiceLog $paper $paperLog @(
        'missing pinned proxy public key:',
        'Done ('
    ) 180
    $negativePaperLogText = Get-Content -Raw -LiteralPath $paperLog
    $negativePinFailureObserved =
        $negativePaperLogText.Contains('missing pinned proxy public key:', [StringComparison]::Ordinal) -or
        $negativePaperLogText.Contains('MCAce requires the trusted proxy identity/server-public-key.txt', [StringComparison]::Ordinal)
    $negativePluginDisabled = $negativePaperLogText.Contains('Disabling MCAce', [StringComparison]::Ordinal)
    $negativeChannelMarkerAbsent = -not $negativePaperLogText.Contains(
        'MCAce signed proxy admission channel enabled', [StringComparison]::Ordinal)
    if (-not $negativePinFailureObserved -or -not $negativePluginDisabled -or -not $negativeChannelMarkerAbsent) {
        throw 'Paper missing-pin case did not prove MCAce disabled without admission channel enablement'
    }
    $negativePaperLog = Join-Path $runRoot 'paper-negative.log'
    Copy-Item -LiteralPath $paperLog -Destination $negativePaperLog
    Stop-JavaService $paper 'stop'
    $paper = $null
    Move-Item -LiteralPath $paperPinBackup -Destination $paperPin
    $paperPinBackup = $null

    $assertions = @(
        'Velocity loaded MCAce and registered its Phase 2 handshake service.',
        'Velocity created a persistent Ed25519 root identity.',
        'Paper loaded MCAce only after receiving the explicit Velocity public-key pin.',
        'Paper reported the same pinned key fingerprint.',
        'Paper rejected MCAce plugin enablement when the Velocity public-key pin was intentionally absent.',
        'Both services reached their ready state on loopback-only ports.'
    )
    if ($WithFabricClient) {
        $assertions += @(
            'A real Fabric 1.21.1 client connected through Velocity and completed the signed MCAce handshake.',
            'Paper accepted the root-signed VERIFIED snapshot for the live carrier player.',
            'The Fabric client exited after its configured smoke completion point.'
        )
    }
    if ($WithFabricEvidence) {
        $assertions += @(
            'A signed GAME_RENDER_FRAME request reached the real Fabric client after authentication.',
            'A human approved the visible, one-shot consent screen; the client uploaded Begin/Chunk/Commit and received COMPLETE.',
            'Velocity recorded a content-free COMPLETE audit summary; raw image retention remained disabled.',
            'The smoke uses no desktop, window, cursor, or operating-system screen-capture API.'
        )
    }
    $report = [ordered]@{
        schema = 1
        status = 'passed'
        run_id = $runId
        completed_at = (Get-Date).ToUniversalTime().ToString('o')
        java = (& java -version 2>&1 | Select-Object -First 1).ToString()
        velocity = [ordered]@{
            version = '3.5.1-615'
            source_url = $velocityArtifact.Url
            expected_sha256 = $velocityArtifact.Sha256
            sha256 = Get-Sha256 $velocityServerJar
            bind = "127.0.0.1:$proxyPort"
            plugin_sha256 = Get-Sha256 $velocityPlugin
            log = $velocityLog
        }
        paper = [ordered]@{
            version = '1.21.1-133'
            source_url = $paperArtifact.Url
            expected_sha256 = $paperArtifact.Sha256
            sha256 = Get-Sha256 $paperServerJar
            bind = "127.0.0.1:$paperPort"
            plugin_sha256 = Get-Sha256 $paperPlugin
            positive_log = $positivePaperLog
            missing_pin_log = $negativePaperLog
        }
        fabric = $fabricReport
        pinned_velocity_key_sha256 = $pinFingerprint
        persistent_identity = [ordered]@{
            fingerprint_before_restart = $identityFingerprintBeforeRestart
            fingerprint_after_restart = $identityFingerprintAfterRestart
            unchanged = ($identityFingerprintBeforeRestart -eq $identityFingerprintAfterRestart)
        }
        channels = [ordered]@{
            velocity_transport_classes_present = $velocityTransportClassesPresent
            paper_admission_channel_enabled = $paperAdmissionChannelEnabled
            no_player_startup_path = $noPlayerStartupPath
        }
        listener_processes = [ordered]@{
            velocity = $velocityListenerPid
            paper = $paperListenerPid
        }
        cleanup_completed = $false
        assertions = $assertions
    }
    $reportPath = Join-Path $runRoot 'report.json'
    [System.IO.File]::WriteAllText(
        $reportPath,
        ($report | ConvertTo-Json -Depth 6),
        [System.Text.UTF8Encoding]::new($false))
    $passed = $true
} catch {
    $smokeFailure = $_
    Write-Error ("PLATFORM_LOAD_SMOKE_FAILURE|{0}|{1}" -f $_.Exception.Message, $_.ScriptStackTrace)
} finally {
    try {
        Stop-JavaService $fabricClient ''
    } catch {
        Write-Warning "Fabric client cleanup failed: $($_.Exception.Message)"
    }
    try {
        Stop-JavaService $paper 'stop'
    } catch {
        Write-Warning "Paper cleanup failed: $($_.Exception.Message)"
    }
    try {
        Stop-JavaService $velocity 'end'
    } catch {
        Write-Warning "Velocity cleanup failed: $($_.Exception.Message)"
    }
    if ($null -ne $paperPinBackup -and (Test-Path -LiteralPath $paperPinBackup) -and
            $null -ne $paperPin -and -not (Test-Path -LiteralPath $paperPin)) {
        Move-Item -LiteralPath $paperPinBackup -Destination $paperPin
    }
    $cleanupPortsFree = (Test-LoopbackPortFree $proxyPort) -and (Test-LoopbackPortFree $paperPort)
    $cleanupCompleted = $cleanupPortsFree
    if ($null -ne $smokeFailure) {
        $failureReport = [ordered]@{
            schema = 1
            status = 'failed'
            run_id = $runId
            completed_at = (Get-Date).ToUniversalTime().ToString('o')
            error = $smokeFailure.Exception.Message
            run_root = $runRoot
            cleanup_completed = $cleanupCompleted
            cleanup_ports_free = $cleanupPortsFree
        }
        $reportPath = Join-Path $runRoot 'report.json'
        [System.IO.File]::WriteAllText(
            $reportPath, ($failureReport | ConvertTo-Json -Depth 6),
            [System.Text.UTF8Encoding]::new($false))
    } elseif ($null -ne $report) {
        $report['cleanup_completed'] = $cleanupCompleted
        $report['cleanup_ports_free'] = $cleanupPortsFree
        [System.IO.File]::WriteAllText(
            $reportPath, ($report | ConvertTo-Json -Depth 6),
            [System.Text.UTF8Encoding]::new($false))
    }
}

if ($null -ne $smokeFailure -or -not $passed -or -not $cleanupCompleted) {
    throw 'MCAce platform load smoke did not complete cleanly; inspect report.json'
}
Write-Output "PLATFORM_LOAD_SMOKE_PASS|$runRoot"
