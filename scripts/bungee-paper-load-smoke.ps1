[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$smokeRoot = Join-Path $repoRoot 'build\platform-smoke-bungee'
$cacheRoot = Join-Path $smokeRoot 'cache'
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
$runRoot = Join-Path $smokeRoot (Join-Path 'runs' $runId)
$bungeeRoot = Join-Path $runRoot 'bungee'
$paperRoot = Join-Path $runRoot 'paper-preferred'
$paperLegacyRoot = Join-Path $runRoot 'paper-legacy'
$paperNoPinRoot = Join-Path $runRoot 'paper-no-pin'
$preparedPaperRoot = Join-Path $repoRoot 'build\platform-smoke\cache\paper-1.21.1-133-prepared'
$reportPath = Join-Path $runRoot 'report.json'
$markdownPath = Join-Path $runRoot 'report.md'
$userAgent = 'MCAce-bungeecord-paper-smoke/0.1 (https://github.com/EllanServer/MCAce)'

$bungeeArtifact = @{
    Name = 'bungeecord-1.21-build-2028.jar'
    Url = 'https://hub.spigotmc.org/jenkins/job/BungeeCord/2028/artifact/bootstrap/target/BungeeCord.jar'
    Sha256 = '45a5aa27b9f2446c320447148913aee5673ec23ddf30c81d6dafa9dd910a91eb'
}
$paperArtifact = @{
    Name = 'paper-1.21.1-133.jar'
    Url = 'https://fill-data.papermc.io/v1/objects/39bd8c00b9e18de91dcabd3cc3dcfa5328685a53b7187a2f63280c22e2d287b9/paper-1.21.1-133.jar'
    Sha256 = '39bd8c00b9e18de91dcabd3cc3dcfa5328685a53b7187a2f63280c22e2d287b9'
}

$ownedServices = [System.Collections.Generic.List[object]]::new()
$cleanupProcessIds = [System.Collections.Generic.List[int]]::new()
$checks = [ordered]@{}
$fixtureResults = [ordered]@{}
$failureMessage = $null
$passed = $false
$cleanupCompleted = $false
$proxyPort = $null
$paperPort = $null
$paperLegacyPort = $null
$paperNoPinPort = $null
$bungeeIdentityPath = $null
$identityFingerprint = $null
$positivePaperLog = $null
$legacyPaperLog = $null
$noPinPaperLog = $null
$bungee = $null
$paper = $null

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-VerifiedArtifact([hashtable]$Artifact) {
    if (($Artifact.Url -notmatch '^https://(hub\.spigotmc\.org/jenkins/job/BungeeCord/\d+/artifact/bootstrap/target/BungeeCord\.jar|fill-data\.papermc\.io/v1/objects/[0-9a-f]{64}/[^/]+)$') -or
            ($Artifact.Sha256 -notmatch '^[0-9a-f]{64}$')) {
        throw "Artifact source or SHA-256 declaration is not an exact official source: $($Artifact.Name)"
    }
    $path = Join-Path $cacheRoot $Artifact.Name
    if (Test-Path -LiteralPath $path -PathType Container) {
        throw "Artifact cache path is a directory: $path"
    }
    if ((Test-Path -LiteralPath $path -PathType Leaf) -and ((Get-Sha256 $path) -ne $Artifact.Sha256)) {
        $quarantine = "$path.invalid-$runId"
        Move-Item -LiteralPath $path -Destination $quarantine
        Write-Warning "Quarantined unexpected cached artifact at $quarantine"
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
            if (Test-Path -LiteralPath $download) { Remove-Item -LiteralPath $download -Force }
        }
    }
    if ((Get-Sha256 $path) -ne $Artifact.Sha256) { throw "Cached artifact failed SHA-256 verification: $($Artifact.Name)" }
    return $path
}

function Get-FreeLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Write-Utf8([string]$Path, [string]$Content) {
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function Protect-IntegrityDirectory([string]$Path) {
    # Paper validates the MCAce pin file against the DACL of its containing
    # directory.  The launcher-created phase tree inherits the controller's
    # broad Users/Authenticated Users ACEs, so harden this exact runtime data
    # directory before any authority file is copied into it.  Keep the helper
    # local to this smoke harness: it does not change the production authority
    # tree or any user-owned directory outside the run root.
    if ([System.IO.Path]::DirectorySeparatorChar -ne '\') { return }
    $resolved = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw "BUNGEE_PAPER_SMOKE_ACL_TARGET_MISSING|$resolved"
    }
    try {
        $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
        $directorySecurity = New-Object System.Security.AccessControl.DirectorySecurity
        $directorySecurity.SetAccessRuleProtection($true, $false)
        $directorySecurity.SetOwner($current)
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        foreach ($sid in @($current, $system)) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow)
            $directorySecurity.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $resolved -AclObject $directorySecurity -ErrorAction Stop
        $readbackAcl = Get-Acl -LiteralPath $resolved -ErrorAction Stop
        if (-not $readbackAcl.AreAccessRulesProtected -or @($readbackAcl.Access).Count -ne 2) {
            throw 'readback DACL was not protected current-user+SYSTEM'
        }
    } catch {
        throw "BUNGEE_PAPER_SMOKE_ACL_HARDENING_FAILED|$resolved|$($_.Exception.Message)"
    }
}

function Test-TextContains([string]$Content, [string]$Needle) {
    return $null -ne $Content -and $Content.IndexOf($Needle, [StringComparison]::Ordinal) -ge 0
}

function Get-JavaVersionText([string]$Executable) {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    Set-ProcessArguments $startInfo @('-version')
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { return '' }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        return $stdout + $stderr
    } finally {
        $process.Dispose()
    }
}

function Set-ProcessArguments(
        [System.Diagnostics.ProcessStartInfo]$StartInfo,
        [string[]]$Arguments) {
    if ($null -ne $StartInfo.PSObject.Properties['ArgumentList']) {
        foreach ($argument in $Arguments) {
            [void]$StartInfo.ArgumentList.Add($argument)
        }
        return
    }

    $StartInfo.Arguments = (@($Arguments | ForEach-Object {
        '"' + ([string]$_).Replace('"', '\"') + '"'
    }) -join ' ')
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
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        foreach ($path in @(Get-ChildItem (Join-Path $env:USERPROFILE '.gradle\jdks\*\bin\java.exe') -File -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty FullName)) {
            $candidates.Add($path)
        }
    }
    foreach ($command in @(Get-Command java.exe -All -ErrorAction SilentlyContinue)) {
        $candidates.Add($command.Source)
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $fallback = $null
    foreach ($candidate in $candidates) {
        if (([string]::IsNullOrWhiteSpace($candidate)) -or (-not (Test-Path -LiteralPath $candidate)) -or
                (-not $seen.Add($candidate))) { continue }
        $versionText = Get-JavaVersionText $candidate
        $match = [regex]::Match($versionText, 'version "(?<major>\d+)')
        if (-not $match.Success) { continue }
        $major = [int]$match.Groups['major'].Value
        if ($major -eq 21) { return $candidate }
        if ($major -ge 21 -and $null -eq $fallback) { $fallback = $candidate }
    }
    if ($null -ne $fallback) { return $fallback }
    throw 'A Java 21+ executable is required for the real Bungee/Paper smoke'
}

function Start-JavaService([string]$Name, [string]$WorkingDirectory, [string]$Jar, [string]$MaximumHeap, [string[]]$ExtraArguments) {
    $java = $script:SmokeJavaPath
    $stdoutPath = Join-Path $WorkingDirectory "$Name.stdout.log"
    $stderrPath = Join-Path $WorkingDirectory "$Name.stderr.log"
    $arguments = @('-Xms128m', "-Xmx$MaximumHeap", '-jar', $Jar) + $ExtraArguments
    $process = Start-Process -FilePath $java -WorkingDirectory $WorkingDirectory -ArgumentList $arguments `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 250
    $current = Get-Process -Id $process.Id -ErrorAction Stop
    $service = [pscustomobject]@{
        Name = $Name; Pid = [int]$process.Id; StartTimeUtc = $current.StartTime.ToUniversalTime(); WorkingDirectory = $WorkingDirectory
        StdoutPath = $stdoutPath; StderrPath = $stderrPath; Process = $process
    }
    [void]$ownedServices.Add($service)
    return $service
}

function Test-OwnedProcess($Service) {
    if ($null -eq $Service) { return $false }
    try {
        $Service.Process.Refresh()
        return -not $Service.Process.HasExited -and $Service.Process.Id -eq $Service.Pid
    } catch { return $false }
}

function Stop-OwnedService($Service) {
    if ($null -eq $Service) { return }
    [void]$cleanupProcessIds.Add([int]$Service.Pid)
    try {
        $Service.Process.Refresh()
        if (-not $Service.Process.HasExited) {
            $Service.Process.Kill()
            if (-not $Service.Process.WaitForExit(20000)) { throw "Owned Java PID $($Service.Pid) did not exit after Kill" }
        }
    } catch [System.ArgumentException] {
        # The exact Process object is already gone; the final runRoot enumeration is authoritative.
    }
    $Service.Process.Refresh()
    if (-not $Service.Process.HasExited) { throw "Owned Java PID $($Service.Pid) did not terminate" }
}

function Get-RunJavaProcesses {
    return Get-RunJavaProcessesForPath $runRoot
}

function Get-RunJavaProcessesForPath([string]$Path) {
    $matches = Get-CimInstance Win32_Process -Filter "Name='java.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $null -ne $_.CommandLine -and $_.CommandLine.IndexOf($Path, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
    return @($matches)
}

function Stop-RunJavaProcess($ProcessRecord) {
    [void]$cleanupProcessIds.Add([int]$ProcessRecord.ProcessId)
    $process = [System.Diagnostics.Process]::GetProcessById([int]$ProcessRecord.ProcessId)
    try {
        $process.Kill()
        if (-not $process.WaitForExit(20000)) { throw "RunRoot Java PID $($ProcessRecord.ProcessId) did not exit" }
    } finally { $process.Dispose() }
}

function Stop-RunJavaProcessesForPath([string]$Path) {
    Start-Sleep -Milliseconds 300
    foreach ($processRecord in @(Get-RunJavaProcessesForPath $Path)) {
        Stop-RunJavaProcess $processRecord
    }
    Start-Sleep -Milliseconds 500
    $remaining = @(Get-RunJavaProcessesForPath $Path)
    if ($remaining.Count -ne 0) {
        throw "Java process residue remained for isolated run root ${Path}: $($remaining.ProcessId -join ',')"
    }
}

function Get-ServiceLogText($Service) {
    $parts = @()
    $logPaths = @($Service.StdoutPath, $Service.StderrPath)
    $bungeeLogs = Get-ChildItem -LiteralPath $Service.WorkingDirectory -File -Filter 'proxy.log.*' -ErrorAction SilentlyContinue
    if ($null -ne $bungeeLogs) { $logPaths += @($bungeeLogs | ForEach-Object { $_.FullName }) }
    $paperLatest = Join-Path $Service.WorkingDirectory 'logs\latest.log'
    if (Test-Path -LiteralPath $paperLatest) { $logPaths += $paperLatest }
    foreach ($path in $logPaths | Select-Object -Unique) {
        if (Test-Path -LiteralPath $path) { $parts += Get-Content -Raw -LiteralPath $path -ErrorAction SilentlyContinue }
    }
    return ($parts -join [Environment]::NewLine)
}

function Wait-ServiceLog($Service, [string[]]$RequiredText, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $content = Get-ServiceLogText $Service
        $ready = $true
        foreach ($text in $RequiredText) {
            if (-not (Test-TextContains $content $text)) { $ready = $false; break }
        }
        if ($ready) { return }
        if (-not (Test-OwnedProcess $Service)) { throw "$($Service.Name) exited before readiness markers were observed`n$content" }
        Start-Sleep -Seconds 1
    }
    throw "$($Service.Name) did not emit readiness markers within $TimeoutSeconds seconds`n$(Get-ServiceLogText $Service)"
}

function Wait-LogOrExit($Service, [string]$RequiredText, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $content = Get-ServiceLogText $Service
        if (Test-TextContains $content $RequiredText) { return $content }
        if (-not (Test-OwnedProcess $Service)) { return $content }
        Start-Sleep -Seconds 1
    }
    throw "$($Service.Name) did not emit expected marker within $TimeoutSeconds seconds`n$(Get-ServiceLogText $Service)"
}

function Copy-ServiceLog($Service, [string]$Destination) { Write-Utf8 $Destination (Get-ServiceLogText $Service) }

function Invoke-GradleFixture([string]$Task, [string]$TestSelector) {
    & (Join-Path $repoRoot 'gradlew.bat') $Task '--tests' $TestSelector '--no-daemon' '--console=plain' 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Fixture test failed: $Task $TestSelector" }
    return 'passed'
}

function Remove-RunFile([string]$Path) {
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $rootWithSeparator = ([System.IO.Path]::GetFullPath($runRoot)).TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($rootWithSeparator, [StringComparison]::OrdinalIgnoreCase)) { throw "Refusing to remove path outside run: $fullPath" }
    if (Test-Path -LiteralPath $fullPath) { Remove-Item -LiteralPath $fullPath -Force }
}

function Write-Reports {
    $status = if ($passed) { 'passed' } else { 'failed' }
    $report = [ordered]@{
        schema = 1; status = $status; run_id = $runId; run_root = $runRoot
        completed_at = (Get-Date).ToUniversalTime().ToString('o')
        java = ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($script:SmokeJavaPath)).ProductVersion
        artifacts = [ordered]@{
            bungeecord = [ordered]@{ version = '1.21'; url = $bungeeArtifact.Url; sha256 = $bungeeArtifact.Sha256 }
            paper = [ordered]@{ version = '1.21.1-133'; url = $paperArtifact.Url; sha256 = $paperArtifact.Sha256 }
            bungee_plugin_sha256 = if (Test-Path -LiteralPath (Join-Path $bungeeRoot 'plugins\mcace.jar')) { Get-Sha256 (Join-Path $bungeeRoot 'plugins\mcace.jar') } else { $null }
            paper_plugin_sha256 = if (Test-Path -LiteralPath (Join-Path $paperRoot 'plugins\mcace.jar')) { Get-Sha256 (Join-Path $paperRoot 'plugins\mcace.jar') } else { $null }
        }
        endpoints = [ordered]@{ bungee = if ($null -eq $proxyPort) { $null } else { "127.0.0.1:$proxyPort" }; paper_preferred = if ($null -eq $paperPort) { $null } else { "127.0.0.1:$paperPort" }; paper_legacy = if ($null -eq $paperLegacyPort) { $null } else { "127.0.0.1:$paperLegacyPort" }; paper_no_pin = if ($null -eq $paperNoPinPort) { $null } else { "127.0.0.1:$paperNoPinPort" }; loopback_only = $true }
        identity = [ordered]@{ public_key = $bungeeIdentityPath; fingerprint_sha256 = $identityFingerprint; generated_by_bungee = [bool]$checks['bungee_identity_generated'] }
        checks = $checks; fixtures = $fixtureResults
        player_connection = [ordered]@{ attempted = $false; connected = $false; limitation = 'No real Minecraft client/player connection was constructed.' }
        backend_injection = [ordered]@{ real_process_connection = $false; code_fixture = ($fixtureResults['bungee_backend_injection_gate'] -eq 'passed'); limitation = 'Backend injection was validated by the shared gate fixture, not a live player plugin message.' }
        logs = [ordered]@{ positive_paper = $positivePaperLog; legacy_paper = $legacyPaperLog; no_pin_paper = $noPinPaperLog; bungee_stdout = Join-Path $bungeeRoot 'bungeecord.stdout.log'; bungee_stderr = Join-Path $bungeeRoot 'bungeecord.stderr.log' }
        cleanup_completed = $cleanupCompleted; owned_pids = @($ownedServices | ForEach-Object { $_.Pid }); cleanup_process_ids = @($cleanupProcessIds | Select-Object -Unique); failure = $failureMessage
        limitations = @('No real Minecraft player connection: live handshake and live Bungee backend admission forwarding remain uncovered.', 'No desktop API, filesystem scan, or client evidence capture was used.')
    }
    Write-Utf8 $reportPath ($report | ConvertTo-Json -Depth 8)
    $markdown = @(
        '# MCAce BungeeCord + Paper process smoke', '',
        "- Status: $status", "- Run: $runId", "- Root: $runRoot",
        "- Bungee endpoint: 127.0.0.1:$proxyPort", "- Paper endpoints: 127.0.0.1:$paperPort / 127.0.0.1:$paperLegacyPort / 127.0.0.1:$paperNoPinPort", "- Cleanup completed: $cleanupCompleted", '',
        '## Verified', '',
        '- Fixed official BungeeCord/Paper URLs and SHA-256 values were checked.',
        '- Current MCAce BungeeCord/Paper shaded jars loaded in real Java processes.',
        '- Bungee generated its persistent identity; Paper accepted preferred and legacy pins.',
        '- Removing both pins kept MCAce disabled (fail closed).',
        '- Signed admission, carrier binding/expiry/replay, identity pin, and backend-injection fixtures passed.', '',
        '## Coverage limitation', '',
        '- No real Minecraft player connection was constructed. Live handshake, backend plugin-message transport, and live admission forwarding are explicitly unclaimed.',
        '- This smoke uses no desktop API and captures no player evidence.', '',
        '## Reports', '', "- JSON: $reportPath", "- Markdown: $markdownPath"
    ) -join [Environment]::NewLine
    Write-Utf8 $markdownPath $markdown
}

$script:SmokeJavaPath = Get-SmokeJava
$env:JAVA_HOME = Split-Path -Parent (Split-Path -Parent $script:SmokeJavaPath)
New-Item -ItemType Directory -Force -Path $cacheRoot, $runRoot, $bungeeRoot, $paperRoot, $paperLegacyRoot, $paperNoPinRoot | Out-Null

try {
    $bungeeServerJar = Get-VerifiedArtifact $bungeeArtifact
    $paperServerJar = Get-VerifiedArtifact $paperArtifact
    & (Join-Path $repoRoot 'gradlew.bat') :mcace-server-bungeecord:shadowJar :mcace-server-paper:shadowJar '--no-daemon' '--console=plain'
    if ($LASTEXITCODE -ne 0) { throw 'MCAce BungeeCord/Paper shaded artifacts did not build successfully' }
    $bungeePlugin = Join-Path $repoRoot 'mcace-server-bungeecord\build\libs\mcace-server-bungeecord-0.1.0-SNAPSHOT.jar'
    $paperPlugin = Join-Path $repoRoot 'mcace-server-paper\build\libs\mcace-server-paper-0.1.0-SNAPSHOT.jar'
    if (-not (Test-Path -LiteralPath $bungeePlugin) -or -not (Test-Path -LiteralPath $paperPlugin)) { throw 'Expected MCAce shaded jars were not produced' }

    $fixtureResults['signed_admission_codec'] = Invoke-GradleFixture ':mcace-core:test' 'com.ellan.mcace.core.admission.SignedAdmissionSnapshotCodecTest'
    $fixtureResults['bungee_backend_injection_gate'] = Invoke-GradleFixture ':mcace-server-bungeecord:test' 'com.ellan.mcace.bungeecord.BungeeInboundFrameGateTest'
    $fixtureResults['paper_signed_admission_receiver'] = Invoke-GradleFixture ':mcace-server-paper:test' 'com.ellan.mcace.paper.PaperAdmissionReceiverTest'
    $fixtureResults['paper_identity_pin_compatibility'] = Invoke-GradleFixture ':mcace-server-paper:test' 'com.ellan.mcace.paper.ProxyIdentityStoreTest'

    $proxyPort = Get-FreeLoopbackPort
    $paperPort = Get-FreeLoopbackPort
    while ($paperPort -eq $proxyPort) { $paperPort = Get-FreeLoopbackPort }
    $paperLegacyPort = Get-FreeLoopbackPort
    while (@($proxyPort, $paperPort) -contains $paperLegacyPort) { $paperLegacyPort = Get-FreeLoopbackPort }
    $paperNoPinPort = Get-FreeLoopbackPort
    while (@($proxyPort, $paperPort, $paperLegacyPort) -contains $paperNoPinPort) {
        $paperNoPinPort = Get-FreeLoopbackPort
    }
    foreach ($preparedDirectoryName in @('cache', 'libraries', 'versions')) {
        $preparedDirectory = Join-Path $preparedPaperRoot $preparedDirectoryName
        if (-not (Test-Path -LiteralPath $preparedDirectory -PathType Container)) { throw "Verified Paper prepared runtime is missing $preparedDirectory" }
    }
    $checks['paper_prepared_runtime_reused'] = $true
    $bungeePlugins = Join-Path $bungeeRoot 'plugins'
    New-Item -ItemType Directory -Force -Path $bungeePlugins | Out-Null
    Copy-Item -LiteralPath $bungeePlugin -Destination (Join-Path $bungeePlugins 'mcace.jar')
    Copy-Item -LiteralPath $bungeeServerJar -Destination (Join-Path $bungeeRoot 'BungeeCord.jar')
    $paperPhaseRoots = @($paperRoot, $paperLegacyRoot, $paperNoPinRoot)
    $paperPhasePorts = @($paperPort, $paperLegacyPort, $paperNoPinPort)
    for ($phaseIndex = 0; $phaseIndex -lt $paperPhaseRoots.Count; $phaseIndex++) {
        $phaseRoot = $paperPhaseRoots[$phaseIndex]
        $phasePort = $paperPhasePorts[$phaseIndex]
        foreach ($preparedDirectoryName in @('cache', 'libraries', 'versions')) {
            Copy-Item -LiteralPath (Join-Path $preparedPaperRoot $preparedDirectoryName) -Destination $phaseRoot -Recurse
        }
        $phasePlugins = Join-Path $phaseRoot 'plugins'
        $phaseDataDirectory = Join-Path $phasePlugins 'MCAce'
        New-Item -ItemType Directory -Force -Path $phasePlugins, $phaseDataDirectory | Out-Null
        Protect-IntegrityDirectory $phaseDataDirectory
        Copy-Item -LiteralPath $paperPlugin -Destination (Join-Path $phasePlugins 'mcace.jar')
        Copy-Item -LiteralPath $paperServerJar -Destination (Join-Path $phaseRoot 'paper.jar')
        Write-Utf8 (Join-Path $phaseRoot 'eula.txt') "eula=true`n"
        Write-Utf8 (Join-Path $phaseRoot 'server.properties') "online-mode=false`nserver-ip=127.0.0.1`nserver-port=$phasePort`nenable-query=false`nmotd=MCAce Bungee Paper smoke`n"
    }
    $bungeeConfig = @"
ip_forward: false
online_mode: false
forge_support: false
listeners:
- query_port: 25577
  motd: '&1MCAce Bungee smoke'
  tab_list: GLOBAL_PING
  query_enabled: false
  proxy_protocol: false
  forced_hosts: {}
  ping_passthrough: false
  priorities:
  - lobby
  bind_local_address: true
  host: 127.0.0.1:$proxyPort
  max_players: 20
  tab_size: 60
  force_default_server: true
timeout: 30000
connection_throttle: 4000
connection_throttle_limit: 3
disabled_commands: []
servers:
  lobby:
    motd: '&1MCAce Paper smoke'
    address: 127.0.0.1:$paperPort
    restricted: false
"@
    Write-Utf8 (Join-Path $bungeeRoot 'config.yml') $bungeeConfig
    $bungee = Start-JavaService 'bungeecord' $bungeeRoot (Join-Path $bungeeRoot 'BungeeCord.jar') '384m' @()
    Wait-ServiceLog $bungee @('MCAce BungeeCord adapter enabled', 'Listening on /127.0.0.1:') 150
    $bungeeIdentityPath = Join-Path $bungeeRoot 'plugins\MCAce\identity\server-public-key.txt'
    $privateIdentityPath = Join-Path $bungeeRoot 'plugins\MCAce\identity\server-private-key.pk8'
    if (-not (Test-Path -LiteralPath $bungeeIdentityPath) -or -not (Test-Path -LiteralPath $privateIdentityPath)) { throw 'Bungee did not create both MCAce identity files' }
    $publicKeyBytes = [Convert]::FromBase64String((Get-Content -Raw -LiteralPath $bungeeIdentityPath).Trim())
    if ($publicKeyBytes.Length -lt 32) { throw 'Bungee identity public key is not a valid Ed25519 encoding' }
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { $identityDigest = $sha256.ComputeHash($publicKeyBytes) }
    finally { $sha256.Dispose() }
    $identityFingerprint = ([System.BitConverter]::ToString($identityDigest)).Replace('-', '').ToLowerInvariant()
    $checks['bungee_identity_generated'] = $true
    $checks['bungee_plugin_loaded'] = Test-TextContains (Get-ServiceLogText $bungee) 'MCAce BungeeCord adapter enabled'
    $checks['bungee_loopback_ready'] = Test-TextContains (Get-ServiceLogText $bungee) 'Listening on /127.0.0.1:'

    $preferredPin = Join-Path (Join-Path $paperRoot 'plugins\MCAce') 'proxy-public-key.txt'
    $legacyPin = Join-Path (Join-Path $paperLegacyRoot 'plugins\MCAce') 'velocity-public-key.txt'
    Copy-Item -LiteralPath $bungeeIdentityPath -Destination $preferredPin
    $paper = Start-JavaService 'paper-preferred' $paperRoot (Join-Path $paperRoot 'paper.jar') '1024m' @('--nogui')
    Wait-ServiceLog $paper @('MCAce signed proxy admission channel enabled', 'Done (') 300
    $positivePaperLog = Join-Path $runRoot 'paper-positive.log'; Copy-ServiceLog $paper $positivePaperLog
    $positiveText = Get-ServiceLogText $paper
    $checks['paper_plugin_loaded'] = Test-TextContains $positiveText 'MCAce signed proxy admission channel enabled'
    $checks['paper_preferred_pin_accepted'] = $positiveText.IndexOf($identityFingerprint, [StringComparison]::OrdinalIgnoreCase) -ge 0
    $checks['signed_admission_channel_enabled'] = $checks['paper_plugin_loaded']
    if (-not $checks['paper_preferred_pin_accepted']) { throw 'Paper did not report the Bungee identity fingerprint' }
    Stop-OwnedService $paper; Stop-RunJavaProcessesForPath $paperRoot; $paper = $null

    Remove-RunFile $preferredPin; Copy-Item -LiteralPath $bungeeIdentityPath -Destination $legacyPin
    $paper = Start-JavaService 'paper-legacy' $paperLegacyRoot (Join-Path $paperLegacyRoot 'paper.jar') '1024m' @('--nogui')
    Wait-ServiceLog $paper @('Using legacy velocity-public-key.txt', 'MCAce signed proxy admission channel enabled', 'Done (') 300
    $legacyPaperLog = Join-Path $runRoot 'paper-legacy.log'; Copy-ServiceLog $paper $legacyPaperLog
    $legacyText = Get-ServiceLogText $paper
    $checks['paper_legacy_pin_accepted'] = (Test-TextContains $legacyText 'Using legacy velocity-public-key.txt') -and (Test-TextContains $legacyText 'MCAce signed proxy admission channel enabled')
    Stop-OwnedService $paper; Stop-RunJavaProcessesForPath $paperLegacyRoot; $paper = $null

    Remove-RunFile $legacyPin
    $paper = Start-JavaService 'paper-no-pin' $paperNoPinRoot (Join-Path $paperNoPinRoot 'paper.jar') '1024m' @('--nogui')
    $noPinText = Wait-LogOrExit $paper 'MCAce requires the trusted proxy identity/server-public-key.txt to be pinned' 120
    $noPinPaperLog = Join-Path $runRoot 'paper-no-pin.log'; Copy-ServiceLog $paper $noPinPaperLog
    $checks['paper_missing_pin_fail_closed'] = (Test-TextContains $noPinText 'MCAce requires the trusted proxy identity/server-public-key.txt to be pinned') -and -not (Test-TextContains $noPinText 'MCAce signed proxy admission channel enabled')
    if (-not $checks['paper_missing_pin_fail_closed']) { throw 'Paper did not fail closed with both proxy pin files absent' }
    Stop-OwnedService $paper; Stop-RunJavaProcessesForPath $paperNoPinRoot; $paper = $null
    $passed = $true
} catch {
    $failureMessage = $_.Exception.Message
    Write-Warning "BUNGEE_PAPER_SMOKE_FAILURE|$failureMessage|$($_.ScriptStackTrace)"
} finally {
    foreach ($service in @($ownedServices)) {
        try { if ($null -ne $service) { Stop-OwnedService $service } }
        catch { $failureMessage = if ($null -eq $failureMessage) { $_.Exception.Message } else { "$failureMessage; cleanup: $($_.Exception.Message)" }; $passed = $false }
    }
    Start-Sleep -Milliseconds 500
    $remaining = Get-RunJavaProcesses
    foreach ($processRecord in @($remaining)) {
        try { Stop-RunJavaProcess $processRecord }
        catch { $failureMessage = if ($null -eq $failureMessage) { $_.Exception.Message } else { "$failureMessage; cleanup-enumeration: $($_.Exception.Message)" }; $passed = $false }
    }
    $remaining = Get-RunJavaProcesses
    if (@($remaining).Count -ne 0) {
        $failureMessage = if ($null -eq $failureMessage) { 'RunRoot Java process residue remained after cleanup' } else { "$failureMessage; RunRoot Java process residue remained after cleanup" }
        $passed = $false
    } else {
        $cleanupCompleted = $true
    }
    try { Write-Reports }
    catch {
        $reportFailure = $_.Exception.Message
        $failureMessage = if ($null -eq $failureMessage) { $reportFailure } else { "$failureMessage; report: $reportFailure" }
        $passed = $false
        Write-Warning "BUNGEE_PAPER_SMOKE_REPORT_FAILURE|$reportFailure|$($_.ScriptStackTrace)"
        $fallback = [ordered]@{ schema = 1; status = 'failed'; run_id = $runId; run_root = $runRoot; cleanup_completed = $cleanupCompleted; failure = $failureMessage }
        [System.IO.File]::WriteAllText($reportPath, ($fallback | ConvertTo-Json -Depth 4), [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText($markdownPath, "# MCAce BungeeCord + Paper process smoke`n`nStatus: failed`nFailure: $failureMessage`nRun root: $runRoot`n", [System.Text.UTF8Encoding]::new($false))
    }
}

if (-not $passed) { throw "Bungee/Paper process smoke failed. See $reportPath" }
Write-Output "Bungee/Paper process smoke passed. JSON: $reportPath; Markdown: $markdownPath"
