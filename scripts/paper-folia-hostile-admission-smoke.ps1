[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Paper', 'Folia')]
    [string]$Platform,
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ServerJar,
    [ValidateSet('1.21.1', '1.21.2', '1.21.3', '1.21.4')]
    [string]$MinecraftVersion = '1.21.1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Local defensive integration only: one caller-supplied server JAR, one ephemeral loopback
# listener, and fixed bounded fixtures. No artifact download, public target, scan, or retained
# identity/frame/key data is part of this gate.
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runRoot = Join-Path $repoRoot ('build\runtime-hostile-admission\runs\' +
    (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ'))
$workRoot = Join-Path $runRoot 'work'
$reportPath = Join-Path $runRoot 'report.json'
$privateKeyPath = Join-Path $workRoot 'proxy-private-key.pk8'
$server = $null
$failure = 'NONE'
$failureStage = 'PREFLIGHT'
$versionCheck = 'NOT_CHECKED'
$artifactCachePreflight = $false
$processApiSupported = $false
$gradleProcessStarted = $false
$gradleProcessExitedZero = $false
$gradleBuildMarkersSeen = $false
$paperOutputRefreshed = $false
$observerOutputRefreshed = $false
$workPrepared = $false
$keyGenerated = $false
$serverProcessStarted = $false
$serverLogCreated = $false
$admissionChannelMarkerSeen = $false
$runtimeMarkerSeen = $false
$observerReadyMarkerSeen = $false
$serverDoneMarkerSeen = $false
$serverReady = $false
$observerReady = $false
$materialRemoved = $false
$cleanupZero = $false
$onlyReportRetained = $false
$results = [ordered]@{
    pinned_baseline_admission_observed = $false
    unpinned_signer_rejected = $false
    wrong_carrier_uuid_rejected = $false
    replay_rejected_after_pinned_baseline = $false
    expired_snapshot_rejected = $false
    oversize_frame_rejected = $false
    wrong_channel_rejected = $false
}

function Get-FreeLoopbackPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Assert-RequiredProcessApi {
    $argumentList = [Diagnostics.ProcessStartInfo].GetProperty('ArgumentList')
    $killTree = @([Diagnostics.Process].GetMethods() | Where-Object {
        $_.Name -eq 'Kill' -and $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType -eq [bool]
    })
    if ($null -eq $argumentList -or $killTree.Count -ne 1) {
        throw 'POWERSHELL_PROCESS_API_UNSUPPORTED'
    }
    if ([string]::IsNullOrWhiteSpace($env:ComSpec) -or
            -not (Test-Path -LiteralPath $env:ComSpec -PathType Leaf)) {
        throw 'POWERSHELL_PROCESS_API_UNSUPPORTED'
    }
    $script:processApiSupported = $true
}

function Resolve-OfflineGradle {
    $gradleUserRoot = if (-not [string]::IsNullOrWhiteSpace($env:GRADLE_USER_HOME)) {
        [IO.Path]::GetFullPath($env:GRADLE_USER_HOME)
    } else {
        Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)) '.gradle'
    }
    $distributionRoot = Join-Path $gradleUserRoot 'wrapper\dists\gradle-9.6.1-bin'
    $executables = @(Get-ChildItem -LiteralPath $distributionRoot -Recurse -Filter gradle.bat -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '[\\/]gradle-9\.6\.1[\\/]bin[\\/]gradle\.bat$' })
    if ($executables.Count -ne 1) { throw 'OFFLINE_GRADLE_DISTRIBUTION_MISSING' }
    $paperApiCache = Join-Path $gradleUserRoot 'caches\modules-2\files-2.1\io.papermc.paper\paper-api\1.21.1-R0.1-SNAPSHOT'
    if (-not (Test-Path -LiteralPath $paperApiCache -PathType Container)) {
        throw 'OFFLINE_DEPENDENCY_CACHE_MISSING'
    }
    return $executables[0].FullName
}

function ConvertTo-CmdQuoted([string]$Value) {
    if ($Value.Contains('"')) { throw 'GRADLE_ARGUMENT_INVALID' }
    return '"' + $Value + '"'
}

function Invoke-OfflineGradle(
        [string]$GradleExecutable,
        [string[]]$Arguments,
        [string[]]$SuccessMarkers,
        [int]$TimeoutSeconds,
        [string]$TimeoutFailure,
        [string]$ExitFailure) {
    $required = @('--offline', '--no-daemon', '--console=plain', '--max-workers=1')
    foreach ($item in $required) {
        if ($Arguments -notcontains $item) { throw 'GRADLE_OFFLINE_ARGUMENT_MISSING' }
    }
    $command = (@($GradleExecutable) + $Arguments | ForEach-Object { ConvertTo-CmdQuoted $_ }) -join ' '
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $env:ComSpec
    $start.WorkingDirectory = $repoRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    [void]$start.ArgumentList.Add('/d')
    [void]$start.ArgumentList.Add('/s')
    [void]$start.ArgumentList.Add('/c')
    [void]$start.ArgumentList.Add($command)
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $started = $false
    $script:gradleProcessStarted = $false
    $script:gradleProcessExitedZero = $false
    try {
        try {
            if (-not $process.Start()) { throw 'GRADLE_PROCESS_START_FAILED' }
        } catch {
            throw 'GRADLE_PROCESS_START_FAILED'
        }
        $started = $true
        $script:gradleProcessStarted = $true
        try {
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
        } catch {
            throw 'GRADLE_STREAM_READ_FAILED'
        }
        try {
            $exited = $process.WaitForExit($TimeoutSeconds * 1000)
        } catch {
            throw 'GRADLE_PROCESS_WAIT_FAILED'
        }
        if (-not $exited) {
            try {
                $process.Kill($true)
                [void]$process.WaitForExit(10000)
            } catch {
                throw 'GRADLE_TIMEOUT_KILL_FAILED'
            }
            throw $TimeoutFailure
        }
        try {
            $capturedOutput = $stdout.GetAwaiter().GetResult() + "`n" +
                $stderr.GetAwaiter().GetResult()
        } catch {
            throw 'GRADLE_STREAM_READ_FAILED'
        }
        try {
            if ($process.ExitCode -ne 0) { throw $ExitFailure }
        } catch {
            if ($_.Exception.Message -eq $ExitFailure) { throw }
            throw 'GRADLE_PROCESS_STATE_FAILED'
        }
        $script:gradleProcessExitedZero = $true
        foreach ($marker in $SuccessMarkers) {
            if ($capturedOutput.IndexOf($marker, [StringComparison]::Ordinal) -lt 0) {
                throw 'GRADLE_SUCCESS_MARKER_MISSING'
            }
        }
    } finally {
        if ($started) {
            try {
                if ($process.HasExited -eq $false) {
                    $process.Kill($true)
                    [void]$process.WaitForExit(10000)
                }
            } catch { }
        }
        try { $process.Dispose() } catch { }
    }
}

function Start-LocalServer([string]$Root, [string]$Jar) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    try {
        $start.FileName = (Get-Command java.exe -ErrorAction Stop).Source
    } catch {
        throw 'JAVA_RUNTIME_UNAVAILABLE'
    }
    $start.WorkingDirectory = $Root
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @('-Xms256m', '-Xmx1024m', '-Dterminal.jline=false', '-Dterminal.ansi=false',
            '-jar', $Jar, '--nogui')) {
        [void]$start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'SERVER_PROCESS_START_FAILED' }
    } catch {
        throw 'SERVER_PROCESS_START_FAILED'
    }
    $script:serverProcessStarted = $true
    try {
        [void]$process.StandardOutput.ReadToEndAsync()
        [void]$process.StandardError.ReadToEndAsync()
    } catch {
        try { $process.Kill($true); [void]$process.WaitForExit(10000) } catch { }
        throw 'SERVER_STREAM_DRAIN_FAILED'
    }
    return $process
}

function Stop-LocalServer([Diagnostics.Process]$Process) {
    if ($null -eq $Process) { return }
    try {
        if (-not $Process.HasExited) {
            try { $Process.StandardInput.WriteLine('stop'); $Process.StandardInput.Flush() } catch { }
            if (-not $Process.WaitForExit(30000)) {
                $Process.Kill($true)
                [void]$Process.WaitForExit(10000)
            }
        }
    } finally {
        $Process.Dispose()
    }
}

function Wait-ForLog([string]$Path, [string[]]$Markers, [Diagnostics.Process]$Process, [int]$Seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $exists = Test-Path -LiteralPath $Path -PathType Leaf
            if ($exists) { $script:serverLogCreated = $true }
            $text = if ($exists) { Get-Content -Raw -LiteralPath $Path } else { '' }
            if ($null -eq $text) { $text = '' }
        } catch {
            throw 'SERVER_LOG_READ_FAILED'
        }
        $script:admissionChannelMarkerSeen =
            $text.IndexOf('MCAce signed proxy admission channel enabled', [StringComparison]::Ordinal) -ge 0
        $script:runtimeMarkerSeen =
            $text.IndexOf("MCAce task runtime=$($Platform.ToUpperInvariant())", [StringComparison]::Ordinal) -ge 0
        $script:observerReadyMarkerSeen =
            $text.IndexOf('MCACE_RUNTIME_OBSERVER_READY', [StringComparison]::Ordinal) -ge 0
        $script:serverDoneMarkerSeen = $text.IndexOf('Done (', [StringComparison]::Ordinal) -ge 0
        if (@($Markers | Where-Object { $text.IndexOf($_, [StringComparison]::Ordinal) -lt 0 }).Count -eq 0) {
            return
        }
        try {
            if ($Process.HasExited) { throw 'SERVER_EXITED_BEFORE_READY' }
        } catch {
            if ($_.Exception.Message -eq 'SERVER_EXITED_BEFORE_READY') { throw }
            throw 'SERVER_PROCESS_STATE_FAILED'
        }
        Start-Sleep -Milliseconds 250
    }
    throw 'SERVER_READY_TIMEOUT'
}

function Get-VersionCheck([string]$Log, [string]$ExpectedPlatform, [string]$ExpectedVersion) {
    $matches = @([regex]::Matches(
        $Log,
        '(?m)\[bootstrap\] Loading (?<platform>Paper|Folia) [^\r\n]* for Minecraft (?<version>1\.21\.[0-9]+)\s*$'))
    if ($matches.Count -eq 0) { return 'BANNER_MISSING' }
    foreach ($match in $matches) {
        if ($match.Groups['platform'].Value -ne $ExpectedPlatform) { return 'PLATFORM_MISMATCH' }
        if ($match.Groups['version'].Value -ne $ExpectedVersion) { return 'VERSION_MISMATCH' }
    }
    return 'VERIFIED'
}

function Get-MarkerCounts([string]$Path) {
    $text = if (Test-Path -LiteralPath $Path) { Get-Content -Raw -LiteralPath $Path } else { '' }
    return [pscustomobject]@{
        accepted = [regex]::Matches($text, '(?m)^.*Accepted signed MCAce admission state.*$').Count
        cleanup = [regex]::Matches($text, '(?m)^.*MCAce player state cleanup completed.*$').Count
        action = [regex]::Matches(
            $text, '(?m)^.*MCACE_RUNTIME_OBSERVER_LOCAL_ADMISSION_ACTION_EXECUTED.*$').Count
    }
}

function Test-CountsEqual([object]$Left, [object]$Right) {
    return $Left.accepted -eq $Right.accepted -and
        $Left.cleanup -eq $Right.cleanup -and $Left.action -eq $Right.action
}

function Get-StableCaseBaseline([string]$LogPath) {
    $candidate = Get-MarkerCounts $LogPath
    $stableUntil = [DateTime]::UtcNow.AddSeconds(1)
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    while ([DateTime]::UtcNow -lt $deadline) {
        $current = Get-MarkerCounts $LogPath
        if (-not (Test-CountsEqual $candidate $current)) { throw 'OLD_MARKER_CROSSED_CASE_BOUNDARY' }
        if ([DateTime]::UtcNow -ge $stableUntil) { return $candidate }
        Start-Sleep -Milliseconds 100
    }
    throw 'MARKER_BASELINE_TIMEOUT'
}

function Wait-StableExpectedDelta(
        [string]$LogPath,
        [object]$Baseline,
        [int]$AcceptedDelta,
        [int]$CleanupDelta,
        [int]$ActionDelta) {
    $expected = [pscustomobject]@{
        accepted = $Baseline.accepted + $AcceptedDelta
        cleanup = $Baseline.cleanup + $CleanupDelta
        action = $Baseline.action + $ActionDelta
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    $stableSince = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $actual = Get-MarkerCounts $LogPath
        if ($actual.accepted -lt $Baseline.accepted -or $actual.cleanup -lt $Baseline.cleanup -or
                $actual.action -lt $Baseline.action) { throw 'MARKER_COUNTER_ROLLBACK' }
        if ($actual.accepted -gt $expected.accepted -or $actual.cleanup -gt $expected.cleanup -or
                $actual.action -gt $expected.action) { throw 'UNEXPECTED_CASE_MARKER' }
        if (Test-CountsEqual $actual $expected) {
            if ($null -eq $stableSince) { $stableSince = [DateTime]::UtcNow }
            if (([DateTime]::UtcNow - $stableSince).TotalMilliseconds -ge 2000) { return $true }
        } else {
            $stableSince = $null
        }
        Start-Sleep -Milliseconds 100
    }
    throw 'CASE_MARKER_STABILITY_TIMEOUT'
}

function Invoke-AdmissionProbe(
        [string]$GradleExecutable,
        [string]$Mode,
        [int]$Port) {
    $probePath = Join-Path $workRoot ($Mode.ToLowerInvariant() + '.json')
    $arguments = @(
        ':mcace-runtime-integration:test',
        '--tests', 'com.ellan.mcace.runtime.FoliaDirectPlayerProbeTest',
        "-Dmcace.folia.player-probe.host=127.0.0.1",
        "-Dmcace.folia.player-probe.port=$Port",
        "-Dmcace.folia.player-probe.minecraft-version=$MinecraftVersion",
        "-Dmcace.folia.player-probe.private-key-path=$privateKeyPath",
        "-Dmcace.folia.player-probe.report-path=$probePath",
        '-Dmcace.folia.player-probe.hold-millis=3500',
        "-Dmcace.admission-probe.mode=$Mode",
        '--rerun-tasks', '--no-build-cache', '--offline', '--no-daemon', '--console=plain', '--max-workers=1')
    Invoke-OfflineGradle $GradleExecutable $arguments @(
        '> Task :mcace-runtime-integration:test', 'BUILD SUCCESSFUL'
    ) 120 'GRADLE_PROBE_TIMEOUT' 'GRADLE_PROBE_FAILED'
    if (-not (Test-Path -LiteralPath $probePath)) { throw 'LOCAL_PROBE_REPORT_MISSING' }
    $probe = Get-Content -Raw -LiteralPath $probePath | ConvertFrom-Json
    Remove-Item -LiteralPath $probePath -Force
    if (-not $probe.login_success -or -not $probe.configuration_finished -or
            -not $probe.payload_dispatch_completed -or $probe.mode -ne $Mode) {
        throw 'LOCAL_PROBE_INCOMPLETE'
    }
    return $probe
}

function Write-SanitizedReport {
    $allAssertions = @($results.Values | Where-Object { -not $_ }).Count -eq 0
    $passed = $processApiSupported -and $artifactCachePreflight -and
        $gradleProcessStarted -and $gradleProcessExitedZero -and $gradleBuildMarkersSeen -and
        $paperOutputRefreshed -and $observerOutputRefreshed -and $workPrepared -and
        $keyGenerated -and $serverProcessStarted -and $serverLogCreated -and
        $serverReady -and $observerReady -and
        $versionCheck -eq 'VERIFIED' -and $allAssertions -and $materialRemoved -and $cleanupZero
    $report = [ordered]@{
        schema = 'PAPER_FOLIA_HOSTILE_ADMISSION_GATE_V3'
        platform = $Platform.ToUpperInvariant()
        failure_stage = $failureStage
        server_version_check = $versionCheck
        powershell_process_api_supported = $processApiSupported
        offline_artifact_cache_preflight = $artifactCachePreflight
        gradle_offline_enforced = $true
        gradle_process_started = $gradleProcessStarted
        gradle_process_exited_zero = $gradleProcessExitedZero
        gradle_build_markers_seen = $gradleBuildMarkersSeen
        paper_output_refreshed = $paperOutputRefreshed
        observer_output_refreshed = $observerOutputRefreshed
        work_prepared = $workPrepared
        key_generated = $keyGenerated
        server_process_started = $serverProcessStarted
        server_log_created = $serverLogCreated
        admission_channel_marker_seen = $admissionChannelMarkerSeen
        runtime_marker_seen = $runtimeMarkerSeen
        observer_ready_marker_seen = $observerReadyMarkerSeen
        server_done_marker_seen = $serverDoneMarkerSeen
        server_ready = $serverReady
        local_action_observer_ready = $observerReady
        pinned_baseline_admission_observed = $results.pinned_baseline_admission_observed
        unpinned_signer_rejected = $results.unpinned_signer_rejected
        wrong_carrier_uuid_rejected = $results.wrong_carrier_uuid_rejected
        replay_rejected_after_pinned_baseline = $results.replay_rejected_after_pinned_baseline
        expired_snapshot_rejected = $results.expired_snapshot_rejected
        oversize_frame_rejected = $results.oversize_frame_rejected
        wrong_channel_rejected = $results.wrong_channel_rejected
        stable_marker_window_enforced = $true
        temporary_material_removed = $materialRemoved
        owned_process_cleanup_zero = $cleanupZero
        only_sanitized_report_retained = $false
        failure = $failure
        case_passed = $passed
    }
    [IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $children = @(Get-ChildItem -LiteralPath $runRoot -Force)
    $script:onlyReportRetained = $children.Count -eq 1 -and
        $children[0].FullName -eq [IO.Path]::GetFullPath($reportPath)
    $report.only_sanitized_report_retained = $script:onlyReportRetained
    $report.case_passed = $passed -and $script:onlyReportRetained
    [IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    return [bool]$report.case_passed
}

New-Item -ItemType Directory -Force -Path $workRoot | Out-Null
try {
    $failureStage = 'PREFLIGHT'
    Assert-RequiredProcessApi
    $resolvedServerJar = (Get-Item -LiteralPath $ServerJar -ErrorAction Stop).FullName
    if ((Get-Item -LiteralPath $resolvedServerJar).Length -le 0) { throw 'SERVER_ARTIFACT_INVALID' }
    $serverCacheRelative = if ($Platform -eq 'Paper') {
        'build\platform-smoke\cache'
    } else {
        'build\platform-smoke-folia\cache'
    }
    $expectedServerCache = [IO.Path]::GetFullPath((Join-Path $repoRoot $serverCacheRelative))
    if (-not $resolvedServerJar.StartsWith(
            $expectedServerCache + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'SERVER_ARTIFACT_OUTSIDE_VERIFIED_CACHE'
    }
    if ([IO.Path]::GetExtension($resolvedServerJar) -ne '.jar') { throw 'SERVER_ARTIFACT_INVALID' }
    $gradleExecutable = Resolve-OfflineGradle
    $artifactCachePreflight = $true

    $failureStage = 'OFFLINE_BUILD'
    $pluginJar = Join-Path $repoRoot 'mcace-server-paper\build\libs\mcace-server-paper-0.1.0-SNAPSHOT.jar'
    $observerJar = Join-Path $repoRoot 'mcace-runtime-integration\build\libs\mcace-runtime-paper-admission-observer-test-only.jar'
    $paperBefore = if (Test-Path -LiteralPath $pluginJar -PathType Leaf) {
        (Get-Item -LiteralPath $pluginJar).LastWriteTimeUtc
    } else { [DateTime]::MinValue }
    $observerBefore = if (Test-Path -LiteralPath $observerJar -PathType Leaf) {
        (Get-Item -LiteralPath $observerJar).LastWriteTimeUtc
    } else { [DateTime]::MinValue }
    Invoke-OfflineGradle $gradleExecutable @(
        ':mcace-server-paper:shadowJar',
        ':mcace-runtime-integration:paperAdmissionObserverJar',
        '--rerun-tasks', '--no-build-cache', '--offline', '--no-daemon', '--console=plain', '--max-workers=1'
    ) @(
        '> Task :mcace-server-paper:shadowJar',
        '> Task :mcace-runtime-integration:paperAdmissionObserverJar',
        'BUILD SUCCESSFUL'
    ) 180 'GRADLE_BUILD_TIMEOUT' 'GRADLE_BUILD_FAILED'
    $gradleBuildMarkersSeen = $true

    if (-not (Test-Path -LiteralPath $pluginJar -PathType Leaf)) { throw 'PAPER_PLUGIN_ARTIFACT_MISSING' }
    if (-not (Test-Path -LiteralPath $observerJar -PathType Leaf)) { throw 'OBSERVER_PLUGIN_ARTIFACT_MISSING' }
    $paperOutputRefreshed = (Get-Item -LiteralPath $pluginJar).LastWriteTimeUtc -gt $paperBefore
    $observerOutputRefreshed = (Get-Item -LiteralPath $observerJar).LastWriteTimeUtc -gt $observerBefore
    if (-not $paperOutputRefreshed) { throw 'PAPER_BUILD_OUTPUT_NOT_REFRESHED' }
    if (-not $observerOutputRefreshed) { throw 'OBSERVER_BUILD_OUTPUT_NOT_REFRESHED' }

    $failureStage = 'PREPARE_WORK'
    $port = Get-FreeLoopbackPort
    New-Item -ItemType Directory -Force -Path (Join-Path $workRoot 'plugins') | Out-Null
    Copy-Item -LiteralPath $resolvedServerJar -Destination (Join-Path $workRoot 'server.jar')
    Copy-Item -LiteralPath $pluginJar -Destination (Join-Path $workRoot 'plugins\mcace.jar')
    Copy-Item -LiteralPath $observerJar -Destination (Join-Path $workRoot 'plugins\mcace-runtime-observer.jar')
    [IO.File]::WriteAllText((Join-Path $workRoot 'eula.txt'), "eula=true`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $workRoot 'server.properties'),
        "online-mode=false`nserver-ip=127.0.0.1`nserver-port=$port`nenable-query=false`nspawn-protection=0`n",
        [Text.UTF8Encoding]::new($false))
    $workPrepared = $true

    $failureStage = 'KEYGEN'
    $keySource = Join-Path $workRoot 'GenerateLocalPin.java'
    [IO.File]::WriteAllText($keySource, @'
import java.security.KeyPairGenerator;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;
public class GenerateLocalPin {
  public static void main(String[] args) throws Exception {
    var generator = KeyPairGenerator.getInstance("Ed25519");
    generator.initialize(NamedParameterSpec.ED25519);
    var pair = generator.generateKeyPair();
    System.out.println(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
    System.out.println(Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
  }
}
'@, [Text.UTF8Encoding]::new($false))
    try {
        $pair = @(& java $keySource 2>$null | ForEach-Object { $_.ToString().Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($LASTEXITCODE -ne 0) { throw 'KEYGEN_PROCESS_FAILED' }
    } catch {
        throw 'KEYGEN_PROCESS_FAILED'
    }
    Remove-Item -LiteralPath $keySource -Force
    if ($pair.Count -ne 2) { throw 'LOCAL_PIN_GENERATION_FAILED' }
    New-Item -ItemType Directory -Force -Path (Join-Path $workRoot 'plugins\MCAce') | Out-Null
    [IO.File]::WriteAllText((Join-Path $workRoot 'plugins\MCAce\proxy-public-key.txt'),
        "$($pair[0])`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($privateKeyPath, "$($pair[1])`n", [Text.UTF8Encoding]::new($false))
    $keyGenerated = $true

    $failureStage = 'START_SERVER'
    $server = Start-LocalServer $workRoot (Join-Path $workRoot 'server.jar')
    $log = Join-Path $workRoot 'logs\latest.log'
    $failureStage = 'WAIT_READY'
    Wait-ForLog $log @(
        'MCAce signed proxy admission channel enabled',
        "MCAce task runtime=$($Platform.ToUpperInvariant())",
        'MCACE_RUNTIME_OBSERVER_READY',
        'Done (') $server 300
    $serverReady = $true
    $observerReady = $true
    $failureStage = 'VERIFY_VERSION'
    try {
        $versionLog = Get-Content -Raw -LiteralPath $log
        if ($null -eq $versionLog) { $versionLog = '' }
    } catch {
        throw 'SERVER_LOG_READ_FAILED'
    }
    $versionCheck = Get-VersionCheck $versionLog $Platform $MinecraftVersion
    if ($versionCheck -ne 'VERIFIED') { throw ('SERVER_VERSION_' + $versionCheck) }

    $failureStage = 'CASE'
    foreach ($case in @(
            [pscustomobject]@{ mode = 'PINNED_BASELINE'; result = 'pinned_baseline_admission_observed'; accepted = 1; action = 1 },
            [pscustomobject]@{ mode = 'UNPINNED_SIGNER'; result = 'unpinned_signer_rejected'; accepted = 0; action = 0 },
            [pscustomobject]@{ mode = 'WRONG_CARRIER_UUID'; result = 'wrong_carrier_uuid_rejected'; accepted = 0; action = 0 },
            [pscustomobject]@{ mode = 'REPLAY'; result = 'replay_rejected_after_pinned_baseline'; accepted = 1; action = 1 },
            [pscustomobject]@{ mode = 'EXPIRED'; result = 'expired_snapshot_rejected'; accepted = 0; action = 0 },
            [pscustomobject]@{ mode = 'OVERSIZE'; result = 'oversize_frame_rejected'; accepted = 0; action = 0 },
            [pscustomobject]@{ mode = 'WRONG_CHANNEL'; result = 'wrong_channel_rejected'; accepted = 0; action = 0 })) {
        $baseline = Get-StableCaseBaseline $log
        $probe = Invoke-AdmissionProbe $gradleExecutable $case.mode $port
        if (-not $probe.hostile_payload_sent -and $case.mode -ne 'PINNED_BASELINE') {
            throw 'HOSTILE_PAYLOAD_NOT_DISPATCHED'
        }
        if ($case.mode -in @('PINNED_BASELINE', 'REPLAY') -and -not $probe.permitted_snapshot_sent) {
            throw 'PERMITTED_BASELINE_NOT_DISPATCHED'
        }
        $results[$case.result] = Wait-StableExpectedDelta $log $baseline $case.accepted 1 $case.action
    }
    $failureStage = 'COMPLETE'
} catch {
    $failure = if ($_.Exception.Message -match '^[A-Z0-9_]+$') {
        $_.Exception.Message
    } else {
        $failureStage + '_INTERNAL_ERROR'
    }
} finally {
    try { Stop-LocalServer $server } catch {
        if ($failure -eq 'NONE') { $failureStage = 'CLEANUP'; $failure = 'SERVER_CLEANUP_FAILED' }
    }
    try {
        if (Test-Path -LiteralPath $workRoot) { Remove-Item -LiteralPath $workRoot -Recurse -Force }
        $materialRemoved = -not (Test-Path -LiteralPath $workRoot)
    } catch {
        if ($failure -eq 'NONE') { $failureStage = 'CLEANUP'; $failure = 'MATERIAL_CLEANUP_FAILED' }
    }
    try {
        $owned = @(Get-CimInstance Win32_Process | Where-Object {
            $_.ProcessId -ne $PID -and
            ([string]$_.CommandLine).IndexOf($workRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0
        })
        $cleanupZero = $owned.Count -eq 0
        if (-not $cleanupZero -and $failure -eq 'NONE') {
            $failureStage = 'CLEANUP'
            $failure = 'OWNED_PROCESS_REMAINS'
        }
    } catch {
        $cleanupZero = $false
        if ($failure -eq 'NONE') {
            $failureStage = 'CLEANUP'
            $failure = 'PROCESS_CLEANUP_INSPECTION_FAILED'
        }
    }
    $passed = Write-SanitizedReport
}

if (-not $passed) { throw "PAPER_FOLIA_HOSTILE_ADMISSION_GATE_FAILED|$reportPath" }
Write-Output "PAPER_FOLIA_HOSTILE_ADMISSION_GATE_PASS|$reportPath"
