[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This smoke is intentionally independent from platform-load-smoke.ps1. It does not
# start a proxy or a client, and it never substitutes a different Minecraft version
# when the requested official Folia artifact is unavailable.
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$smokeRoot = Join-Path $repoRoot 'build\platform-smoke-folia'
$cacheRoot = Join-Path $smokeRoot 'cache'
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
$runRoot = Join-Path $smokeRoot (Join-Path 'runs' $runId)
$positiveRoot = Join-Path $runRoot 'positive'
$negativeRoot = Join-Path $runRoot 'missing-pin'
$userAgent = 'MCAce-folia-process-smoke/0.1 (https://github.com/EllanServer/MCAce)'
$targetVersion = '1.21.1'
$minecraftVersion = $targetVersion
$officialProjectUri = 'https://fill.papermc.io/v3/projects/folia'
$officialBuildsUri = "$officialProjectUri/versions/$targetVersion/builds"

$startedServices = [System.Collections.Generic.List[object]]::new()
$report = [ordered]@{
    schema = 2
    status = 'running'
    run_id = $runId
    started_at = (Get-Date).ToUniversalTime().ToString('o')
    completed_at = $null
    target_requested = $targetVersion
    tested_version = $null
    exact_version_available = $null
    official_api = [ordered]@{
        project_url = $officialProjectUri
        builds_url = $officialBuildsUri
        user_agent = $userAgent
        project_response = $null
        builds_response = [ordered]@{ exact = $null; tested = $null }
        selected_build = $null
    }
    artifact = $null
    plugin = $null
    positive = $null
    player_probe = $null
    missing_pin = $null
    processes = [System.Collections.Generic.List[object]]::new()
    assertions = [System.Collections.Generic.List[string]]::new()
    failure = $null
    cleanup = [ordered]@{
        attempted = $false
        run_process_ids_before_cleanup = @()
        force_killed_process_ids = @()
        forced_kill = $false
        live_process_ids_after_cleanup = @()
        error = $null
        error_script_line = $null
        error_invocation = $null
        error_script_stack = $null
    }
}

function Write-JsonReport {
    $report.completed_at = (Get-Date).ToUniversalTime().ToString('o')
    $reportPath = Join-Path $runRoot 'report.json'
    [System.IO.File]::WriteAllText(
        $reportPath,
        ($report | ConvertTo-Json -Depth 12),
        [System.Text.UTF8Encoding]::new($false))
    $report.report_path = $reportPath
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Save-ApiResponse([object]$Response, [string]$Path) {
    [System.IO.File]::WriteAllText(
        $Path,
        ($Response | ConvertTo-Json -Depth 20),
        [System.Text.UTF8Encoding]::new($false))
}

function Invoke-OfficialJson([string]$Uri) {
    # Use the OS curl binary rather than Invoke-WebRequest. Windows PowerShell 5.1
    # has neither -SkipHttpErrorCheck nor reliable JSON error-body handling.  Fill
    # deliberately returns an error document for a version which does not exist.
    $responsePath = [System.IO.Path]::GetTempFileName()
    try {
        $status = & curl.exe --silent --show-error --location --user-agent $userAgent --output $responsePath --write-out '%{http_code}' $Uri
        if ($LASTEXITCODE -ne 0) {
            throw "curl failed while retrieving official API $Uri (exit $LASTEXITCODE)"
        }
        $content = [System.IO.File]::ReadAllText($responsePath)
        if ([string]::IsNullOrWhiteSpace($content)) {
            throw "official API returned HTTP $status without a JSON body for $Uri"
        }
        return $content | ConvertFrom-Json
    } finally {
        Remove-Item -LiteralPath $responsePath -Force -ErrorAction SilentlyContinue
    }
}

function Get-OfficialFoliaArtifact {
    $projectResponse = Invoke-OfficialJson $officialProjectUri
    $projectPath = Join-Path $runRoot 'official-project.json'
    Save-ApiResponse $projectResponse $projectPath
    $report.official_api.project_response = $projectPath

    $exactResponse = Invoke-OfficialJson $officialBuildsUri
    $exactPath = Join-Path $runRoot 'official-builds-1.21.1.json'
    Save-ApiResponse $exactResponse $exactPath
    $report.official_api.builds_response.exact = $exactPath

    $testedVersion = $targetVersion
    $exactAvailable = $true
    $buildsResponse = $exactResponse
    $exactApiOk = $exactResponse.PSObject.Properties['ok']
    if ($null -ne $exactApiOk -and $exactApiOk.Value -eq $false) {
        $exactAvailable = $false
        $availableVersions = @($projectResponse.versions.'1.21') |
            Where-Object { $_ -match '^1\.21\.\d+$' } |
            Sort-Object { [Version]$_ }
        $testedVersion = $availableVersions |
            Where-Object { ([Version]$_) -ge [Version]$targetVersion } |
            Select-Object -First 1
        if ([string]::IsNullOrWhiteSpace($testedVersion)) {
            throw "FOLIA_SMOKE_BLOCKED|official API has no available Folia 1.21.x version at or above $targetVersion"
        }
        $fallbackUri = "$officialProjectUri/versions/$testedVersion/builds"
        $buildsResponse = Invoke-OfficialJson $fallbackUri
        $fallbackPath = Join-Path $runRoot "official-builds-$($testedVersion.Replace('.', '-')).json"
        Save-ApiResponse $buildsResponse $fallbackPath
        $report.official_api.builds_response.tested = $fallbackPath
    } else {
        $report.official_api.builds_response.tested = $exactPath
    }
    $testedApiOk = $buildsResponse.PSObject.Properties['ok']
    if ($null -ne $testedApiOk -and $testedApiOk.Value -eq $false) {
        $apiError = $buildsResponse.PSObject.Properties['error']
        $apiMessage = $buildsResponse.PSObject.Properties['message']
        throw "FOLIA_SMOKE_BLOCKED|official API rejected tested Folia version ${testedVersion}: $($apiError.Value) - $($apiMessage.Value)"
    }
    $builds = @($buildsResponse)
    if ($builds.Count -eq 0) {
        throw "FOLIA_SMOKE_BLOCKED|official API returned no Folia builds for tested version $testedVersion"
    }

    $selected = $builds |
        Where-Object { $_.channel -in @('STABLE', 'RECOMMENDED') } |
        Sort-Object -Property id -Descending |
        Select-Object -First 1
    if ($null -eq $selected) {
        $selected = $builds | Sort-Object -Property id -Descending | Select-Object -First 1
    }
    if ($null -eq $selected) {
        throw "FOLIA_SMOKE_BLOCKED|official API returned no usable Folia build for tested version $testedVersion"
    }
    $download = $selected.downloads.'server:default'
    if ($null -eq $download -or [string]::IsNullOrWhiteSpace($download.url) -or [string]::IsNullOrWhiteSpace($download.checksums.sha256)) {
        throw "FOLIA_SMOKE_BLOCKED|selected official Folia build has no server:default URL and SHA-256"
    }
    $report.official_api.selected_build = [ordered]@{
        tested_version = $testedVersion
        exact_version_available = $exactAvailable
        id = $selected.id
        channel = $selected.channel
        url = $download.url
        sha256 = $download.checksums.sha256.ToLowerInvariant()
    }
    return [pscustomobject]@{
        Name = "folia-$testedVersion-$($selected.id).jar"
        Url = $download.url
        Sha256 = $download.checksums.sha256.ToLowerInvariant()
        BuildId = $selected.id
        Channel = $selected.channel
        MinecraftVersion = $testedVersion
        ExactVersionAvailable = $exactAvailable
    }
}

function Get-VerifiedArtifact([object]$Artifact) {
    New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null
    $path = Join-Path $cacheRoot $Artifact.Name
    if ((Test-Path -LiteralPath $path) -and (Get-Sha256 $path) -ne $Artifact.Sha256) {
        $quarantine = "$path.invalid-$runId"
        Move-Item -LiteralPath $path -Destination $quarantine
        throw "cached Folia artifact had an unexpected SHA-256; quarantined at $quarantine"
    }
    if (-not (Test-Path -LiteralPath $path)) {
        $download = "$path.download-$runId"
        Invoke-WebRequest -Headers @{ 'User-Agent' = $userAgent } -Uri $Artifact.Url -OutFile $download
        if ((Get-Sha256 $download) -ne $Artifact.Sha256) {
            Remove-Item -LiteralPath $download -Force
            throw "downloaded Folia artifact failed SHA-256 verification: $($Artifact.Name)"
        }
        Move-Item -LiteralPath $download -Destination $path
    }
    if ((Get-Sha256 $path) -ne $Artifact.Sha256) {
        throw "cached Folia artifact failed SHA-256 verification: $($Artifact.Name)"
    }
    return $path
}

function Get-FreeLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Start-JavaService([string]$Name, [string]$WorkingDirectory, [string]$Jar, [int]$Port) {
    $java = (Get-Command java.exe -ErrorAction Stop).Source
    $stdoutPath = Join-Path $WorkingDirectory "$Name.stdout.log"
    $stderrPath = Join-Path $WorkingDirectory "$Name.stderr.log"
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $java
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $arguments = @(
        '-Xms256m', '-Xmx1024m', '-Dterminal.jline=false', '-Dterminal.ansi=false',
        '-jar', $Jar, '--nogui')
    if ($startInfo.PSObject.Properties.Match('ArgumentList').Count -gt 0) {
        foreach ($argument in $arguments) {
            [void]$startInfo.ArgumentList.Add($argument)
        }
    } else {
        # ProcessStartInfo.ArgumentList was added after the Windows PowerShell 5.1
        # runtime. These harness arguments are controlled values; quote each value
        # so a workspace path containing spaces still reaches Java as one argument.
        $startInfo.Arguments = (($arguments | ForEach-Object {
            '"' + ([string]$_).Replace('"', '\"') + '"'
        }) -join ' ')
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw "could not start $Name" }
    $service = [pscustomobject]@{
        name = $Name
        process = $process
        pid = $process.Id
        port = $Port
        server_log_path = Join-Path $WorkingDirectory 'logs\latest.log'
        stdout_path = $stdoutPath
        stderr_path = $stderrPath
        forced_kill = $false
    }
    [void]$startedServices.Add($service)
    [void]$report.processes.Add([ordered]@{ name = $Name; pid = $process.Id; port = $Port })
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    [void](Add-Member -InputObject $service -NotePropertyName stdout_task -NotePropertyValue $stdoutTask)
    [void](Add-Member -InputObject $service -NotePropertyName stderr_task -NotePropertyValue $stderrTask)
    return $service
}

function Stop-JavaService([object]$Service, [string]$Command) {
    if ($null -eq $Service) { return }
    $process = $Service.process
    if (-not $process.HasExited) {
        if (-not [string]::IsNullOrWhiteSpace($Command)) {
            try {
                $process.StandardInput.WriteLine($Command)
                $process.StandardInput.Flush()
            } catch { }
        }
        if (-not $process.WaitForExit(30000)) {
            $process.Kill($true)
            [void]$process.WaitForExit(10000)
            $Service.forced_kill = $true
            $report.cleanup.forced_kill = $true
        }
    }
    $stdout = if ($Service.stdout_task.Wait(5000)) { $Service.stdout_task.Result } else { '' }
    $stderr = if ($Service.stderr_task.Wait(5000)) { $Service.stderr_task.Result } else { '' }
    [System.IO.File]::WriteAllText(
        $Service.stdout_path, $stdout, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        $Service.stderr_path, $stderr, [System.Text.UTF8Encoding]::new($false))
    $process.Dispose()
}

function Get-RunProcesses {
    return @(Get-CimInstance Win32_Process | Where-Object {
        if ($null -eq $_ -or $_.ProcessId -eq $PID) { return $false }
        $commandLine = [string]$_.CommandLine
        return $commandLine.IndexOf($runRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0
    })
}

function Clear-RunProcesses {
    $before = @(Get-RunProcesses)
    $report.cleanup.run_process_ids_before_cleanup = @($before | ForEach-Object { $_.ProcessId })
    $remaining = $before
    for ($attempt = 0; $attempt -lt 30 -and $remaining.Count -gt 0; $attempt++) {
        Start-Sleep -Seconds 1
        $remaining = @(Get-RunProcesses)
    }
    $forced = [System.Collections.Generic.List[int]]::new()
    foreach ($process in $remaining) {
        try {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
            $forced.Add([int]$process.ProcessId)
        } catch { }
    }
    $report.cleanup.force_killed_process_ids = @($forced)
    if ($forced.Count -gt 0) { $report.cleanup.forced_kill = $true }
    Start-Sleep -Seconds 2
    $after = @(Get-RunProcesses)
    $report.cleanup.live_process_ids_after_cleanup = @($after | ForEach-Object { $_.ProcessId })
    if ($after.Count -gt 0) {
        throw "Folia smoke left run-scoped processes alive: $($after.ProcessId -join ', ')"
    }
}

function Wait-Log([object]$Service, [string[]]$RequiredText, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $path = $Service.server_log_path
    while ([DateTime]::UtcNow -lt $deadline) {
        $content = ''
        if (Test-Path -LiteralPath $path) {
            $content = Get-Content -Raw -LiteralPath $path -ErrorAction SilentlyContinue
            if ($null -eq $content) { $content = '' }
        }
        $allPresent = $true
        foreach ($text in $RequiredText) {
            if ($content.IndexOf($text, [StringComparison]::Ordinal) -lt 0) {
                $allPresent = $false
                break
            }
        }
        if ($allPresent) { return }
        if ($Service.process.HasExited) {
            throw "$($Service.name) exited before readiness markers were observed"
        }
        Start-Sleep -Seconds 1
    }
    throw "$($Service.name) did not emit readiness markers within $TimeoutSeconds seconds"
}

function Write-ServerFiles([string]$Root, [int]$Port) {
    New-Item -ItemType Directory -Force -Path $Root, (Join-Path $Root 'plugins') | Out-Null
    [System.IO.File]::WriteAllText(
        (Join-Path $Root 'eula.txt'), "eula=true`n", [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        (Join-Path $Root 'server.properties'),
        "online-mode=false`nserver-ip=127.0.0.1`nserver-port=$Port`nenable-query=false`nspawn-protection=0`nmotd=MCAce Folia process smoke`n",
        [System.Text.UTF8Encoding]::new($false))
}

function New-Ed25519TestKeyPair([string]$PublicPath, [string]$PrivatePath) {
    $source = Join-Path $runRoot 'GenerateEd25519Pin.java'
    [System.IO.File]::WriteAllText($source, @'
import java.security.KeyPairGenerator;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;
public class GenerateEd25519Pin {
  public static void main(String[] args) throws Exception {
    var generator = KeyPairGenerator.getInstance("Ed25519");
    generator.initialize(NamedParameterSpec.ED25519);
    var pair = generator.generateKeyPair();
    System.out.println(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
    System.out.println(Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
  }
}
'@, [System.Text.UTF8Encoding]::new($false))
    try {
        $encoded = @(& java $source 2>$null | ForEach-Object { $_.ToString().Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($encoded.Count -ne 2) { throw 'Ed25519 test-key generator returned an incomplete key pair' }
        New-Item -ItemType Directory -Force -Path ([System.IO.Path]::GetDirectoryName($PublicPath)), ([System.IO.Path]::GetDirectoryName($PrivatePath)) | Out-Null
        [System.IO.File]::WriteAllText($PublicPath, "$($encoded[0])`n", [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText($PrivatePath, "$($encoded[1])`n", [System.Text.UTF8Encoding]::new($false))
    } finally {
        Remove-Item -LiteralPath $source -Force -ErrorAction SilentlyContinue
    }
}

function Test-NoFoliaThreadErrors([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { throw "missing Folia log: $Path" }
    $text = Get-Content -Raw -LiteralPath $Path
    $matches = @([regex]::Matches($text, '(?im)(AsyncCatcher|IllegalStateException|IllegalPluginAccessException|thread check|not owned by region|scheduler invocation failed)'))
    return [pscustomobject]@{
        passed = ($matches.Count -eq 0)
        matches = @($matches | ForEach-Object { $_.Value })
    }
}

New-Item -ItemType Directory -Force -Path $runRoot, $positiveRoot, $negativeRoot | Out-Null
$pluginPath = $null
$foliaService = $null
$admissionPrivateKeyPath = $null
$passed = $false

try {
    & (Join-Path $repoRoot 'gradlew.bat') :mcace-server-paper:shadowJar --no-daemon --no-configuration-cache
    if ($LASTEXITCODE -ne 0) { throw 'MCAce Paper shadow JAR did not build successfully' }
    $pluginPath = Join-Path $repoRoot 'mcace-server-paper\build\libs\mcace-server-paper-0.1.0-SNAPSHOT.jar'
    if (-not (Test-Path -LiteralPath $pluginPath)) { throw 'expected MCAce Paper shadow JAR was not produced' }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($pluginPath)
    try {
        $pluginEntry = $archive.GetEntry('plugin.yml')
        if ($null -eq $pluginEntry) { throw 'MCAce Paper JAR does not contain plugin.yml' }
        $reader = [System.IO.StreamReader]::new($pluginEntry.Open(), [System.Text.Encoding]::UTF8)
        try { $pluginYml = $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $archive.Dispose() }
    if ($pluginYml -notmatch '(?m)^\s*folia-supported:\s*true\s*$') {
        throw 'plugin.yml does not declare folia-supported: true'
    }
    $apiLine = ($pluginYml -split "`r?`n" | Where-Object { $_ -match '^\s*api-version:' } | Select-Object -First 1)
    $apiVersion = ($apiLine -replace '^\s*api-version:\s*', '').Trim().Trim("'").Trim('"')
    $report.plugin = [ordered]@{
        path = $pluginPath
        sha256 = Get-Sha256 $pluginPath
        folia_supported = $true
        api_version = $apiVersion
    }
    if ($report.plugin.api_version -ne '1.21') {
        throw "plugin.yml api-version is not the expected compatible 1.21 value: $($report.plugin.api_version)"
    }
    $report.assertions.Add('MCAce Paper shadow JAR was built and declares folia-supported: true.')

    $artifact = Get-OfficialFoliaArtifact
    $foliaJar = Get-VerifiedArtifact $artifact
    $report.artifact = [ordered]@{
        path = $foliaJar
        name = $artifact.Name
        url = $artifact.Url
        minecraft_version = $artifact.MinecraftVersion
        target_requested = $targetVersion
        tested_version = $artifact.MinecraftVersion
        exact_version_available = $artifact.ExactVersionAvailable
        build_id = $artifact.BuildId
        channel = $artifact.Channel
        sha256 = Get-Sha256 $foliaJar
    }
    $report.tested_version = $artifact.MinecraftVersion
    $report.exact_version_available = $artifact.ExactVersionAvailable
    $report.assertions.Add("Official Folia API resolved target $targetVersion to tested version $($artifact.MinecraftVersion), build $($artifact.BuildId), with an immutable SHA-256 cache check.")
    New-Item -ItemType Directory -Force -Path (Join-Path $positiveRoot 'plugins'), (Join-Path $negativeRoot 'plugins') | Out-Null
    Copy-Item -LiteralPath $pluginPath -Destination (Join-Path $positiveRoot 'plugins\mcace.jar')
    Copy-Item -LiteralPath $pluginPath -Destination (Join-Path $negativeRoot 'plugins\mcace.jar')
    Copy-Item -LiteralPath $foliaJar -Destination (Join-Path $positiveRoot 'folia.jar')
    Copy-Item -LiteralPath $foliaJar -Destination (Join-Path $negativeRoot 'folia.jar')

    $port = Get-FreeLoopbackPort
    Write-ServerFiles $negativeRoot $port
    $foliaService = Start-JavaService 'folia-missing-pin' $negativeRoot (Join-Path $negativeRoot 'folia.jar') $port
    Wait-Log $foliaService @('MCAce requires the trusted proxy identity/server-public-key.txt', 'Done (') 300
    Stop-JavaService $foliaService 'stop'
    $foliaService = $null
    $missingLog = Join-Path $negativeRoot 'logs\latest.log'
    $missingText = Get-Content -Raw -LiteralPath $missingLog
    if ($missingText.IndexOf('MCAce signed proxy admission channel enabled', [StringComparison]::Ordinal) -ge 0) {
        throw 'Folia loaded MCAce despite the trusted proxy pin being absent'
    }
    $report.missing_pin = [ordered]@{
        status = 'failed_closed'
        port = $port
        log = $missingLog
        stdout = Join-Path $negativeRoot 'folia-missing-pin.stdout.log'
        stderr = Join-Path $negativeRoot 'folia-missing-pin.stderr.log'
        marker = 'MCAce requires the trusted proxy identity/server-public-key.txt'
    }
    $report.assertions.Add('Folia refused MCAce enablement when the trusted proxy pin was absent.')

    $positivePort = Get-FreeLoopbackPort
    Write-ServerFiles $positiveRoot $positivePort
    $pin = Join-Path $positiveRoot 'plugins\MCAce\proxy-public-key.txt'
    $admissionPrivateKeyPath = Join-Path $positiveRoot 'admission-test-private-key.pk8'
    New-Ed25519TestKeyPair $pin $admissionPrivateKeyPath
    $foliaService = Start-JavaService 'folia-positive' $positiveRoot (Join-Path $positiveRoot 'folia.jar') $positivePort
    Wait-Log $foliaService @(
        'MCAce signed proxy admission channel enabled',
        'MCAce task runtime=FOLIA',
        'Done ('
    ) 300
    $probeReportPath = Join-Path $positiveRoot 'folia-direct-player-probe.json'
    & (Join-Path $repoRoot 'gradlew.bat') :mcace-runtime-integration:test `
        '--tests' 'com.ellan.mcace.runtime.FoliaDirectPlayerProbeTest' `
        "-Dmcace.folia.player-probe.host=127.0.0.1" `
        "-Dmcace.folia.player-probe.port=$positivePort" `
        "-Dmcace.folia.player-probe.minecraft-version=$($artifact.MinecraftVersion)" `
        "-Dmcace.folia.player-probe.private-key-path=$admissionPrivateKeyPath" `
        "-Dmcace.folia.player-probe.report-path=$probeReportPath" `
        '-Dmcace.folia.player-probe.hold-millis=4500' `
        '--no-daemon' '--console=plain'
    if ($LASTEXITCODE -ne 0) { throw 'Folia direct player probe did not complete successfully' }
    if (-not (Test-Path -LiteralPath $probeReportPath)) { throw 'Folia direct player probe did not emit a report' }
    $playerProbe = Get-Content -Raw -LiteralPath $probeReportPath | ConvertFrom-Json
    if (-not $playerProbe.login_success -or -not $playerProbe.configuration_finished -or
            -not $playerProbe.payload_dispatch_completed -or -not $playerProbe.permitted_snapshot_sent -or
            $playerProbe.hostile_payload_sent) {
        throw 'Folia direct player probe did not complete the bounded login/configuration/admission path'
    }
    Wait-Log $foliaService @(
        'Accepted signed MCAce admission state',
        'Expired signed MCAce admission state',
        'MCAce player state cleanup completed'
    ) 30
    if (Test-Path -LiteralPath $admissionPrivateKeyPath) { Remove-Item -LiteralPath $admissionPrivateKeyPath -Force }
    $admissionPrivateKeyPath = $null
    $positiveLog = Join-Path $positiveRoot 'logs\latest.log'
    $positiveText = Get-Content -Raw -LiteralPath $positiveLog
    $threadCheck = Test-NoFoliaThreadErrors $positiveLog
    if (-not $threadCheck.passed) {
        throw "Folia scheduler/thread error markers found: $($threadCheck.matches -join ', ')"
    }
    $report.positive = [ordered]@{
        status = 'loaded'
        port = $positivePort
        log = $positiveLog
        stdout = Join-Path $positiveRoot 'folia-positive.stdout.log'
        stderr = Join-Path $positiveRoot 'folia-positive.stderr.log'
        proxy_pin = $pin
        proxy_pin_sha256 = Get-Sha256 $pin
        runtime_marker = 'MCAce task runtime=FOLIA'
        global_scheduler = 'exercised by MCAce repeatGlobal admission expiration'
        entity_scheduler = 'exercised by a real test-only player C2S admission payload and PlayerQuit cleanup'
        thread_error_scan = [ordered]@{
            passed = $threadCheck.passed
            matches = @($threadCheck.matches)
            scanned_log = $positiveLog
            excluded_logs = @($missingLog)
            missing_pin_expected_exception_excluded = $true
        }
    }
    $report.player_probe = [ordered]@{
        status = 'passed'
        report = $probeReportPath
        minecraft_protocol = $playerProbe.protocol
        login_success = $playerProbe.login_success
        configuration_finished = $playerProbe.configuration_finished
        signed_admission_sent = $playerProbe.permitted_snapshot_sent
        lifecycle_markers = @(
            'Accepted signed MCAce admission state',
            'Expired signed MCAce admission state',
            'MCAce player state cleanup completed'
        )
        private_test_key_retained = $false
    }
    $report.assertions.Add('Folia loaded MCAce with a valid Ed25519 proxy pin and selected the FOLIA scheduler runtime.')
    $report.assertions.Add('Folia global expiration, entity-owned admission consumption, admission expiry, and PlayerQuit cleanup completed through one real test-only player connection.')
    $report.status = 'passed'
    $passed = $true
} catch {
    $message = $_.Exception.Message
    if ($message.StartsWith('FOLIA_SMOKE_BLOCKED|', [StringComparison]::Ordinal)) {
        $report.status = 'blocked'
        $report.failure = $message.Substring('FOLIA_SMOKE_BLOCKED|'.Length)
    } else {
        $report.status = 'failed'
        $report.failure = $message
        Write-Error ("FOLIA_PROCESS_SMOKE_FAILURE|{0}|{1}" -f $message, $_.ScriptStackTrace)
    }
} finally {
    $report.cleanup.attempted = $true
    try {
        if ($null -ne $admissionPrivateKeyPath -and (Test-Path -LiteralPath $admissionPrivateKeyPath)) {
            Remove-Item -LiteralPath $admissionPrivateKeyPath -Force -ErrorAction SilentlyContinue
        }
    } catch {
        $report.status = 'failed'
        $passed = $false
        if ($null -eq $report.failure) {
            $report.failure = "could not remove ephemeral Folia admission test key: $($_.Exception.Message)"
        }
    }
    try {
        if ($null -ne $foliaService) { Stop-JavaService $foliaService 'stop' }
    } catch {
        $cleanupError = $_
        $report.status = 'failed'
        $passed = $false
        $report.cleanup.error = $cleanupError.Exception.Message
        if ($null -ne $cleanupError.InvocationInfo) {
            $report.cleanup.error_script_line = $cleanupError.InvocationInfo.ScriptLineNumber
            $report.cleanup.error_invocation = $cleanupError.InvocationInfo.PositionMessage
        }
        $report.cleanup.error_script_stack = $cleanupError.ScriptStackTrace
        if ($null -eq $report.failure) { $report.failure = "cleanup: $($cleanupError.Exception.Message)" }
    }
    try { Clear-RunProcesses } catch {
        $cleanupError = $_
        $report.status = 'failed'
        $passed = $false
        $report.cleanup.error = $cleanupError.Exception.Message
        if ($null -ne $cleanupError.InvocationInfo) {
            $report.cleanup.error_script_line = $cleanupError.InvocationInfo.ScriptLineNumber
            $report.cleanup.error_invocation = $cleanupError.InvocationInfo.PositionMessage
        }
        $report.cleanup.error_script_stack = $cleanupError.ScriptStackTrace
        if ($null -eq $report.failure) { $report.failure = "cleanup: $($cleanupError.Exception.Message)" }
    }
    Write-JsonReport
}

if (-not $passed) {
    Write-Output "FOLIA_PROCESS_SMOKE_$($report.status.ToUpperInvariant())|$($report.report_path)"
    throw "Folia process smoke did not pass: $($report.status) - $($report.failure)"
}
Write-Output "FOLIA_PROCESS_SMOKE_PASS|$($report.report_path)"
