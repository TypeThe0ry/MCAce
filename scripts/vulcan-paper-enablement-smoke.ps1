[CmdletBinding(DefaultParameterSetName = 'Execute')]
param(
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [switch]$Execute,
    [Parameter(ParameterSetName = 'Report', Mandatory)] [switch]$ReportOnly,
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [string]$VulcanJar,
    [Parameter(Mandatory)] [string]$VulcanSha256,
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [string]$PaperJar,
    [Parameter(Mandatory)] [string]$PaperSha256,
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [string]$MCAceJar,
    [Parameter(Mandatory)] [string]$MCAceSha256,
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [string]$PreparedRoot,
    [Parameter(Mandatory)] [string]$PreparedManifestSha256,
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [switch]$AllowTemporaryPaperRemap,
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [ValidateSet('DenyAll')] [string]$NetworkPolicy,
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [switch]$NetworkIsolationAttested,
    [ValidateRange(1, 1440)] [int]$MaximumReportAgeMinutes = 60
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runsRoot = Join-Path $repoRoot 'build\vulcan-paper-enablement\runs'
$wrapperPath = Join-Path $PSScriptRoot 'vulcan-paper-enablement-smoke.ps1'
$reportSchema = 'MCACE_VULCAN_PAPER_ENABLEMENT_V1'
$bindingSchema = 'MCACE_VULCAN_PAPER_ENABLEMENT_BINDING_V1'
$reviewedVulcanSha256 = '7ee3a4fdd7e9da5269f9efc327478e507563e6e7df7abec2222acd3b499bc993'
function ConvertTo-Sha256([string]$Value, [string]$Field) {
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "VULCAN_ENABLEMENT_INVALID_SHA256: $Field" }
    $normalized = $Value.Trim().ToLowerInvariant()
    if ($normalized -notmatch '^[0-9a-f]{64}$') { throw "VULCAN_ENABLEMENT_INVALID_SHA256: $Field" }
    return $normalized
}
function Assert-ExpectedPreparedManifest([string]$Actual, [string]$Expected) {
    if ($Actual -cne $Expected) {
        throw 'VULCAN_ENABLEMENT_PREPARED_MANIFEST_HASH_MISMATCH'
    }
}
function Get-BytesSha256([byte[]]$Bytes) {
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hasher.Dispose() }
}
function Get-PathBinding([string]$Path) {
    $resolved = Assert-DirectLocalPath $Path; $stream = $null
    try {
        $stream = [System.IO.File]::Open($resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $sha = ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $hasher.Dispose() }
        return [pscustomobject]@{path = $resolved; length = [long]$stream.Length; sha256 = $sha}
    } finally { if ($null -ne $stream) { $stream.Dispose() } }
}
function Assert-DirectLocalPath([string]$Path, [switch]$Directory) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('"') -or
            -not [System.IO.Path]::IsPathRooted($Path) -or $Path -notmatch '^[A-Za-z]:[\\/]') {
        throw 'VULCAN_ENABLEMENT_ABSOLUTE_LOCAL_PATH_REQUIRED'
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    $drive = [System.IO.DriveInfo]::new($root)
    if ($drive.DriveType -ne [System.IO.DriveType]::Fixed) {
        throw 'VULCAN_ENABLEMENT_FIXED_LOCAL_DRIVE_REQUIRED'
    }
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($Directory -and -not $item.PSIsContainer) { throw 'VULCAN_ENABLEMENT_DIRECTORY_REQUIRED' }
    if (-not $Directory -and $item.PSIsContainer) { throw 'VULCAN_ENABLEMENT_FILE_REQUIRED' }
    $cursorPath = $item.FullName
    while (-not [string]::IsNullOrWhiteSpace($cursorPath)) {
        $cursor = Get-Item -LiteralPath $cursorPath -Force -ErrorAction Stop
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'VULCAN_ENABLEMENT_REPARSE_PATH_REJECTED'
        }
        $parent = Split-Path -Path $cursorPath -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursorPath) { break }
        $cursorPath = $parent
    }
    return $item.FullName
}
function Assert-DescendantPath([string]$Root, [string]$Path) {
    $resolvedRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $prefix = $resolvedRoot + [System.IO.Path]::DirectorySeparatorChar
    if (-not $resolvedPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'VULCAN_ENABLEMENT_PATH_ESCAPED_ISOLATED_ROOT'
    }
    return $resolvedPath
}
function Open-LockedJar([string]$Path, [string]$ExpectedSha256) {
    $resolved = Assert-DirectLocalPath $Path
    if ([System.IO.Path]::GetExtension($resolved) -ne '.jar') { throw 'VULCAN_ENABLEMENT_JAR_REQUIRED' }
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($resolved, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        if ($stream.Length -le 0) { throw 'VULCAN_ENABLEMENT_EMPTY_ARTIFACT' }
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        try { $actual = ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $hasher.Dispose() }
        $stream.Position = 0
        if ($actual -ne $ExpectedSha256) { throw 'VULCAN_ENABLEMENT_ARTIFACT_HASH_MISMATCH' }
        return [pscustomobject]@{ path = $resolved; length = [long]$stream.Length; stream = $stream }
    } catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}
function Assert-PreparedAssets([string]$Path, [string]$ExpectedManifestSha256) {
    $resolved = Assert-DirectLocalPath $Path -Directory
    foreach ($name in @('cache', 'libraries', 'versions')) {
        $directory = Assert-DirectLocalPath (Join-Path $resolved $name) -Directory
        $firstFile = Get-ChildItem -LiteralPath $directory -Recurse -Force -File | Select-Object -First 1
        if ($null -eq $firstFile) { throw 'VULCAN_ENABLEMENT_PREPARED_CACHE_INCOMPLETE' }
    }
    $entries = @()
    foreach ($entry in Get-ChildItem -LiteralPath $resolved -Recurse -Force) {
        if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'VULCAN_ENABLEMENT_PREPARED_CACHE_REPARSE_REJECTED'
        }
        if (-not $entry.PSIsContainer) {
            $relative = $entry.FullName.Substring($resolved.Length + 1).Replace('\', '/')
            if ($relative -match '^(cache|libraries|versions)/') {
                $file = Get-PathBinding $entry.FullName
                $entries += "$relative|$($file.length)|$($file.sha256)"
            }
        }
    }
    $ordered = @($entries | Sort-Object)
    if ($ordered.Count -eq 0) { throw 'VULCAN_ENABLEMENT_PREPARED_CACHE_INCOMPLETE' }
    $manifest = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes(($ordered -join "`n")))
    Assert-ExpectedPreparedManifest $manifest $ExpectedManifestSha256
    return [pscustomobject]@{ path = $resolved; manifest_sha256 = $manifest; file_count = [int]$ordered.Count }
}

function Get-RemapState([string[]]$ArtifactPaths) {
    $entries = [System.Collections.Generic.List[string]]::new()
    foreach ($artifact in $ArtifactPaths) {
        $parent = Assert-DirectLocalPath (Split-Path -Parent $artifact) -Directory
        $remap = Join-Path $parent '.paper-remapped'
        if (-not (Test-Path -LiteralPath $remap)) { continue }
        $resolvedRemap = Assert-DirectLocalPath $remap -Directory
        $entries.Add("$parent|.paper-remapped|directory")
        foreach ($file in @(Get-ChildItem -LiteralPath $resolvedRemap -Recurse -Force -File)) {
            $binding = Get-PathBinding $file.FullName
            $relative = $binding.path.Substring($resolvedRemap.Length + 1).Replace('\', '/')
            $entries.Add("$parent|$relative|$($binding.length)|$($binding.sha256)")
        }
    }
    $ordered = @($entries.ToArray() | Sort-Object)
    return [pscustomobject]@{
        manifest_sha256 = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes(($ordered -join "`n")))
        file_count = [int]$ordered.Count
    }
}
function Get-CurrentBinding {
    if ([string]::IsNullOrWhiteSpace($env:JAVA_HOME)) { throw 'VULCAN_ENABLEMENT_JAVA_HOME_21_REQUIRED' }
    $java = Get-PathBinding (Join-Path $env:JAVA_HOME 'bin\java.exe')
    $version = [string](Get-Item -LiteralPath $java.path).VersionInfo.FileVersion
    if ($version -notmatch '^21(?:\.|$)') { throw 'VULCAN_ENABLEMENT_JAVA_HOME_21_REQUIRED' }
    $sources = [ordered]@{
        paper_plugin = 'mcace-server-paper/src/main/java/com/ellan/mcace/paper/MCAcePaperPlugin.java'
        integration_config = 'mcace-server-paper/src/main/java/com/ellan/mcace/paper/PaperIntegrationConfiguration.java'
        vulcan_integration = 'mcace-server-paper/src/main/java/com/ellan/mcace/paper/behavior/VulcanBehaviorIntegration.java'
        vulcan_contract = 'mcace-server-paper/src/main/java/com/ellan/mcace/paper/behavior/VulcanApiCompatibility.java'
        default_config = 'mcace-server-paper/src/main/resources/config.yml'; plugin_metadata = 'mcace-server-paper/src/main/resources/plugin.yml'
    }
    $entries = foreach ($entry in $sources.GetEnumerator()) {
        $file = Get-PathBinding (Join-Path $repoRoot $entry.Value); "$($entry.Key)|$($file.length)|$($file.sha256)"
    }
    $manifest = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes(($entries -join "`n")))
    $wrapper = Get-PathBinding $wrapperPath
    return [pscustomobject]@{wrapper_sha256 = $wrapper.sha256; source_manifest_sha256 = $manifest
        source_file_count = [int]$sources.Count; java_path = $java.path
        java_executable_sha256 = $java.sha256; java_file_version = $version}
}
function Get-FreePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try { $listener.Start(); return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}
function Write-ServerConfiguration([string]$ServerRoot, [int]$Port, [string]$PreparedRoot) {
    foreach ($directory in @('cache', 'libraries', 'versions')) {
        Copy-Item -LiteralPath (Join-Path $PreparedRoot $directory) `
            -Destination (Join-Path $ServerRoot $directory) -Recurse -Force
    }
    $data = Join-Path $ServerRoot 'plugins\MCAce'
    $bstats = Join-Path $ServerRoot 'plugins\bStats'
    New-Item -ItemType Directory -Force -Path $data, $bstats | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $ServerRoot 'eula.txt'), "eula=true`n",
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $ServerRoot 'server.properties'),
        "online-mode=false`nserver-ip=127.0.0.1`nserver-port=$Port`nenable-query=false`nspawn-protection=0`nmotd=MCAce licensed Vulcan enablement gate`n",
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $bstats 'config.yml'), "enabled: false`n",
        [System.Text.UTF8Encoding]::new($false))
    # Public RFC 8032 test-vector material; it is not a production identity or secret.
    [System.IO.File]::WriteAllText((Join-Path $data 'proxy-public-key.txt'),
        "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=`n",
        [System.Text.Encoding]::ASCII)
    [System.IO.File]::WriteAllBytes((Join-Path $data 'cloud-server-private-key.pk8'),
        [Convert]::FromBase64String('MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g'))
    [System.IO.File]::WriteAllText((Join-Path $data 'config.yml'), @'
session-actions:
  mode: MONITOR
behavior:
  enabled: true
  minimum-flags: 1
  window-seconds: 10
  cooldown-seconds: 30
  maximum-tracked-keys: 32
  grim:
    enabled: false
  vulcan:
    enabled: true
cloud:
  enabled: true
  endpoint: "http://127.0.0.1:9"
  server-id: "vulcan-enablement-gate"
  private-key-path: "cloud-server-private-key.pk8"
  queue-capacity: 8
  request-timeout-ms: 250
'@, [System.Text.UTF8Encoding]::new($false))
}
function ConvertTo-ProcessArgument([string]$Value) {
    if ($Value.Contains('"')) { throw 'VULCAN_ENABLEMENT_PROCESS_ARGUMENT_INVALID' }; return '"' + $Value + '"'
}
function Get-MarkerProcesses([string]$Marker) {
    return @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.CommandLine) -and
        ([string]$_.CommandLine).IndexOf($Marker, [StringComparison]::Ordinal) -ge 0
    })
}
function Test-OwnedProcess([Diagnostics.Process]$Process, [int]$ExpectedId,
        [datetime]$ExpectedStartTimeUtc, [string]$Marker) {
    if ($null -eq $Process -or $Process.HasExited -or $Process.Id -ne $ExpectedId) { return $false }
    $Process.Refresh()
    if ($Process.StartTime.ToUniversalTime() -ne $ExpectedStartTimeUtc) { return $false }
    $records = @(Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ExpectedId" -ErrorAction Stop)
    return $records.Count -eq 1 -and
        ([string]$records[0].CommandLine).IndexOf($Marker, [StringComparison]::Ordinal) -ge 0
}
function Stop-OwnedProcess([Diagnostics.Process]$Process, [int]$ExpectedId,
        [datetime]$ExpectedStartTimeUtc, [string]$Marker) {
    if ($Process.HasExited) { return }
    if (-not (Test-OwnedProcess $Process $ExpectedId $ExpectedStartTimeUtc $Marker)) {
        throw 'VULCAN_ENABLEMENT_PROCESS_OWNERSHIP_UNPROVEN'
    }
    $treeKill = [Diagnostics.Process].GetMethods() | Where-Object {
        $_.Name -eq 'Kill' -and $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType -eq [bool]
    } | Select-Object -First 1
    if ($null -ne $treeKill) { [void]$treeKill.Invoke($Process, @($true)) }
    else { $Process.Kill() }
    if (-not $Process.WaitForExit(30000)) { throw 'VULCAN_ENABLEMENT_PROCESS_DID_NOT_EXIT' }
}
function Get-JsonPropertyNames([object]$Value) { return @($Value.PSObject.Properties | ForEach-Object Name) }
function Test-ExactProperties([object]$Value, [string[]]$Expected) {
    $actual = @(Get-JsonPropertyNames $Value | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    return $actual.Count -eq $wanted.Count -and (($actual -join "`n") -ceq ($wanted -join "`n"))
}
function Test-JsonString([object]$Value) { return $Value -is [string] }
function Test-JsonBoolean([object]$Value) { return $Value -is [bool] }
function Test-JsonInteger([object]$Value) { return $Value -is [byte] -or $Value -is [int16] -or
    $Value -is [int32] -or $Value -is [int64] }
function Assert-SanitizedEvidence([string]$Raw) {
    if ($Raw.Length -gt 32768 -or
            $Raw -match '(?i)[A-Z]:[\\/]|\\\\|(?:^|["\s])/(?:home|users|tmp|var|opt|mnt|root)/' -or
            $Raw -match '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b') {
        throw 'VULCAN_ENABLEMENT_EVIDENCE_NOT_SANITIZED'
    }
}
function Open-LockedEvidence([string]$Path) {
    $resolved = Assert-DirectLocalPath $Path
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($resolved, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        if ($stream.Length -le 0 -or $stream.Length -gt 32768) { throw 'VULCAN_ENABLEMENT_EVIDENCE_SIZE_INVALID' }
        $memory = [System.IO.MemoryStream]::new()
        try { $stream.CopyTo($memory); $bytes = $memory.ToArray() }
        finally { $memory.Dispose() }
        $encoding = [System.Text.UTF8Encoding]::new($false, $true)
        $raw = $encoding.GetString($bytes)
        Assert-SanitizedEvidence $raw
        return [pscustomobject]@{ raw = $raw; sha256 = Get-BytesSha256 $bytes; stream = $stream }
    } catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}
function Assert-ReportRaw([string]$Raw, [string]$ExpectedVulcan, [string]$ExpectedPaper, [string]$ExpectedMCAce) {
    $names = @('schema', 'generated_at', 'source_mode', 'vulcan_sha256', 'paper_sha256',
        'mcace_sha256', 'vulcan_size', 'paper_size', 'mcace_size', 'plugin_name', 'plugin_version',
        'network_policy', 'network_isolation_operator_attested', 'network_isolation_os_verified_by_script',
        'paper_process_coverage', 'licensed_plugin_enablement_coverage',
        'mcace_listener_registration_coverage', 'real_behavior_event_delivery_coverage',
        'temporary_paper_remap_allowed', 'temporary_material_removed', 'remaining_marker_process_count',
        'limitations', 'passed')
    try { $report = $Raw | ConvertFrom-Json -ErrorAction Stop } catch { throw 'VULCAN_ENABLEMENT_REPORT_JSON_INVALID' }
    if (-not (Test-ExactProperties $report $names)) { throw 'VULCAN_ENABLEMENT_REPORT_PROPERTIES_INVALID' }
    foreach ($name in @('schema', 'generated_at', 'source_mode', 'vulcan_sha256', 'paper_sha256',
            'mcace_sha256', 'plugin_name', 'plugin_version', 'network_policy')) {
        if (-not (Test-JsonString $report.$name)) { throw 'VULCAN_ENABLEMENT_REPORT_TYPE_INVALID' }
    }
    foreach ($name in @('network_isolation_operator_attested', 'network_isolation_os_verified_by_script',
            'paper_process_coverage', 'licensed_plugin_enablement_coverage',
            'mcace_listener_registration_coverage', 'real_behavior_event_delivery_coverage',
            'temporary_paper_remap_allowed', 'temporary_material_removed', 'passed')) {
        if (-not (Test-JsonBoolean $report.$name)) { throw 'VULCAN_ENABLEMENT_REPORT_TYPE_INVALID' }
    }
    foreach ($name in @('vulcan_size', 'paper_size', 'mcace_size', 'remaining_marker_process_count')) {
        if (-not (Test-JsonInteger $report.$name)) { throw 'VULCAN_ENABLEMENT_REPORT_TYPE_INVALID' }
    }
    $timestamp = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact($report.generated_at, 'o',
            [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$timestamp)) {
        throw 'VULCAN_ENABLEMENT_REPORT_TIMESTAMP_INVALID'
    }
    $age = [DateTimeOffset]::UtcNow - $timestamp
    if ($age.TotalMinutes -lt 0 -or $age.TotalMinutes -gt $MaximumReportAgeMinutes) {
        throw 'VULCAN_ENABLEMENT_REPORT_STALE'
    }
    $limitations = @($report.limitations)
    if ($limitations.Count -ne 3 -or
            $limitations[0] -cne 'ENABLEMENT_AND_LISTENER_REGISTRATION_ONLY' -or
            $limitations[1] -cne 'REAL_BEHAVIOR_EVENT_DELIVERY_NOT_COVERED' -or
            $limitations[2] -cne 'NETWORK_ISOLATION_OPERATOR_ATTESTED_NOT_OS_VERIFIED_BY_SCRIPT') {
        throw 'VULCAN_ENABLEMENT_REPORT_LIMITATIONS_INVALID'
    }
    if ($report.schema -cne $reportSchema -or $report.source_mode -cne 'EXECUTED_OPERATOR_NETWORK_ATTESTED' -or
            $report.vulcan_sha256 -cne $ExpectedVulcan -or $report.paper_sha256 -cne $ExpectedPaper -or
            $report.mcace_sha256 -cne $ExpectedMCAce -or $report.vulcan_size -le 0 -or
            $report.paper_size -le 0 -or $report.mcace_size -le 0 -or
            $report.plugin_name -cne 'Vulcan' -or $report.plugin_version -cne '2.9.0' -or
            $report.network_policy -cne 'DENY_ALL_OPERATOR_ATTESTATION' -or
            -not $report.network_isolation_operator_attested -or $report.network_isolation_os_verified_by_script -or
            -not $report.paper_process_coverage -or -not $report.licensed_plugin_enablement_coverage -or
            -not $report.mcace_listener_registration_coverage -or $report.real_behavior_event_delivery_coverage -or
            -not $report.temporary_paper_remap_allowed -or -not $report.temporary_material_removed -or
            $report.remaining_marker_process_count -ne 0 -or -not $report.passed) {
        throw 'VULCAN_ENABLEMENT_REPORT_INVALID'
    }
    return $report
}
function Assert-BindingRaw([string]$Raw, [string]$ReportSha256, [object]$Report,
        [string]$ExpectedVulcan, [string]$ExpectedPaper, [string]$ExpectedMCAce,
        [string]$ExpectedPrepared) {
    $names = @('schema', 'report_schema', 'report_generated_at', 'report_sha256', 'source_mode',
        'vulcan_sha256', 'paper_sha256', 'mcace_sha256', 'wrapper_sha256', 'source_manifest_sha256',
        'source_file_count', 'java_executable_sha256', 'java_file_version',
        'prepared_manifest_sha256', 'prepared_file_count', 'passed')
    try { $binding = $Raw | ConvertFrom-Json -ErrorAction Stop } catch { throw 'VULCAN_ENABLEMENT_BINDING_JSON_INVALID' }
    if (-not (Test-ExactProperties $binding $names)) { throw 'VULCAN_ENABLEMENT_BINDING_PROPERTIES_INVALID' }
    foreach ($name in @($names | Where-Object { $_ -notin @('passed', 'source_file_count', 'prepared_file_count') })) {
        if (-not (Test-JsonString $binding.$name)) { throw 'VULCAN_ENABLEMENT_BINDING_TYPE_INVALID' }
    }
    $current = Get-CurrentBinding
    if (-not (Test-JsonBoolean $binding.passed) -or -not (Test-JsonInteger $binding.source_file_count) -or
            -not (Test-JsonInteger $binding.prepared_file_count) -or
            $binding.schema -cne $bindingSchema -or
            $binding.report_schema -cne $reportSchema -or $binding.report_generated_at -cne $Report.generated_at -or
            $binding.report_sha256 -cne $ReportSha256 -or
            $binding.source_mode -cne 'EXECUTED_OPERATOR_NETWORK_ATTESTED' -or
            $binding.vulcan_sha256 -cne $ExpectedVulcan -or $binding.paper_sha256 -cne $ExpectedPaper -or
            $binding.mcace_sha256 -cne $ExpectedMCAce -or $binding.wrapper_sha256 -cne $current.wrapper_sha256 -or
            $binding.source_manifest_sha256 -cne $current.source_manifest_sha256 -or
            $binding.source_file_count -ne $current.source_file_count -or
            $binding.java_executable_sha256 -cne $current.java_executable_sha256 -or
            $binding.java_file_version -cne $current.java_file_version -or
            $binding.prepared_manifest_sha256 -cne $ExpectedPrepared -or
            $binding.prepared_file_count -le 0 -or -not $binding.passed) {
        throw 'VULCAN_ENABLEMENT_BINDING_INVALID'
    }
    Assert-ExpectedPreparedManifest $binding.prepared_manifest_sha256 $ExpectedPrepared
}
function Assert-EvidencePair([string]$ReportPath, [string]$ExpectedVulcan,
        [string]$ExpectedPaper, [string]$ExpectedMCAce, [string]$ExpectedPrepared) {
    $reportEvidence = $null
    $bindingEvidence = $null
    try {
        $reportEvidence = Open-LockedEvidence $ReportPath
        $bindingEvidence = Open-LockedEvidence (Join-Path (Split-Path $ReportPath -Parent) 'binding.json')
        $report = Assert-ReportRaw $reportEvidence.raw $ExpectedVulcan $ExpectedPaper $ExpectedMCAce
        Assert-BindingRaw $bindingEvidence.raw $reportEvidence.sha256 $report `
            $ExpectedVulcan $ExpectedPaper $ExpectedMCAce $ExpectedPrepared
        return $report
    } finally {
        if ($null -ne $bindingEvidence) { $bindingEvidence.stream.Dispose() }
        if ($null -ne $reportEvidence) { $reportEvidence.stream.Dispose() }
    }
}
function Get-LatestReport {
    if (-not (Test-Path -LiteralPath $runsRoot -PathType Container)) { return $null }
    return Get-ChildItem -LiteralPath $runsRoot -Directory -Force |
        Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 } |
        ForEach-Object { Get-Item -LiteralPath (Join-Path $_.FullName 'report.json') -ErrorAction SilentlyContinue } |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1 -ExpandProperty FullName
}
$expectedVulcan = ConvertTo-Sha256 $VulcanSha256 'VulcanSha256'
$expectedPaper = ConvertTo-Sha256 $PaperSha256 'PaperSha256'
$expectedMCAce = ConvertTo-Sha256 $MCAceSha256 'MCAceSha256'
$expectedPrepared = ConvertTo-Sha256 $PreparedManifestSha256 'PreparedManifestSha256'
if ($expectedVulcan -ne $reviewedVulcanSha256) { throw 'VULCAN_ENABLEMENT_UNREVIEWED_VULCAN_HASH' }
if ($ReportOnly) {
    foreach ($name in @('VulcanJar', 'PaperJar', 'MCAceJar', 'PreparedRoot')) {
        if ($PSBoundParameters.ContainsKey($name)) { throw 'VULCAN_ENABLEMENT_REPORT_ONLY_PATH_REJECTED' }
    }
    $path = Get-LatestReport
    if ($null -eq $path) { throw 'VULCAN_ENABLEMENT_REPORT_REQUIRED' }
    $null = Assert-EvidencePair $path $expectedVulcan $expectedPaper $expectedMCAce $expectedPrepared
    Write-Output 'VULCAN_PAPER_ENABLEMENT_PASS|report-only'
    exit 0
}
if (-not $Execute -or -not $AllowTemporaryPaperRemap -or $NetworkPolicy -ne 'DenyAll' -or
        -not $NetworkIsolationAttested) {
    throw 'VULCAN_ENABLEMENT_EXPLICIT_EXECUTION_REMAP_AND_NETWORK_ATTESTATION_REQUIRED'
}
$lockedVulcan = $null; $lockedPaper = $null; $lockedMCAce = $null
try {
    $lockedVulcan = Open-LockedJar $VulcanJar $expectedVulcan
    $lockedPaper = Open-LockedJar $PaperJar $expectedPaper
    $lockedMCAce = Open-LockedJar $MCAceJar $expectedMCAce
    $preparedBinding = Assert-PreparedAssets $PreparedRoot $expectedPrepared
    $currentBinding = Get-CurrentBinding; $java = $currentBinding.java_path
    $resolvedRepo = Assert-DirectLocalPath $repoRoot -Directory
    if (-not (Test-Path -LiteralPath $runsRoot)) { New-Item -ItemType Directory -Path $runsRoot | Out-Null }
    $null = Assert-DirectLocalPath $runsRoot -Directory
    $runToken = [guid]::NewGuid().ToString('N')
    $runRoot = Assert-DescendantPath $runsRoot (Join-Path $runsRoot $runToken)
    $serverRoot = Assert-DescendantPath $runRoot (Join-Path $runRoot 'server')
    New-Item -ItemType Directory -Path $serverRoot | Out-Null
    $processMarker = "mcace-vulcan-paper-enablement-$runToken"
    $remapBefore = Get-RemapState @($lockedVulcan.path, $lockedPaper.path, $lockedMCAce.path)
    $process = $null
    $processId = 0
    $processStartTimeUtc = [datetime]::MinValue
    $temporaryRemoved = $false
    $remaining = 0
    $passed = $false
    $cleanupFailure = $null
    try {
        Write-ServerConfiguration $serverRoot (Get-FreePort) $preparedBinding.path
        $isolatedPrepared = Assert-PreparedAssets $serverRoot $expectedPrepared
        if ($isolatedPrepared.file_count -ne $preparedBinding.file_count) {
            throw 'VULCAN_ENABLEMENT_ISOLATED_PREPARED_COPY_COUNT_MISMATCH'
        }
        $stdout = Join-Path $serverRoot 'paper.stdout.log'
        $stderr = Join-Path $serverRoot 'paper.stderr.log'
        $arguments = @('-Dpaper.disableStartupVersionCheck=true', "-Dmcace.vulcan.enablement.run=$processMarker",
            '-Xms512m', '-Xmx1024m', '-jar', $lockedPaper.path, '--nogui',
            '--add-plugin', $lockedVulcan.path, '--add-plugin', $lockedMCAce.path)
        $argumentLine = ($arguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' '
        $process = Start-Process -FilePath $java -ArgumentList $argumentLine -WorkingDirectory $serverRoot `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
        $processId = $process.Id
        $processStartTimeUtc = $process.StartTime.ToUniversalTime()
        if (-not (Test-OwnedProcess $process $processId $processStartTimeUtc $processMarker)) {
            throw 'VULCAN_ENABLEMENT_STARTED_PROCESS_OWNERSHIP_UNPROVEN'
        }
        $deadline = [DateTime]::UtcNow.AddSeconds(150)
        $adapterObserved = $false
        $vulcanObserved = $false
        $paperReadyObserved = $false
        do {
            Start-Sleep -Milliseconds 250
            $text = ''
            if (Test-Path -LiteralPath $stdout) { $text += Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue }
            if (Test-Path -LiteralPath $stderr) { $text += Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue }
            $vulcanObserved = $text -match '(?im)^.*\[Vulcan\] Enabling Vulcan v2\.9\.0\s*$'
            $adapterObserved = $text -match [regex]::Escape(
                'MCAce Vulcan behavior adapter enabled (observational, no automatic punishment)')
            $paperReadyObserved = $text -match '(?im)^.*Done \([0-9.]+s\)! For help, type "help"\s*$'
            if ($process.HasExited -and -not ($vulcanObserved -and $adapterObserved -and $paperReadyObserved)) {
                throw 'VULCAN_ENABLEMENT_PAPER_EXITED_EARLY'
            }
        } while (-not ($vulcanObserved -and $adapterObserved -and $paperReadyObserved) -and
            [DateTime]::UtcNow -lt $deadline)
        if (-not ($vulcanObserved -and $adapterObserved -and $paperReadyObserved)) {
            throw 'VULCAN_ENABLEMENT_MARKERS_TIMEOUT'
        }
        $passed = $true
    } finally {
        try {
            if ($null -ne $process) {
                Stop-OwnedProcess $process $processId $processStartTimeUtc $processMarker
                $process.Dispose()
            }
            $remaining = @(Get-MarkerProcesses $processMarker).Count
            if ($remaining -ne 0) { throw 'VULCAN_ENABLEMENT_MARKER_PROCESS_REMAINED' }
        } catch { $cleanupFailure = $_.Exception.Message }
        try {
            if (Test-Path -LiteralPath $serverRoot) {
                $null = Assert-DescendantPath $runRoot $serverRoot
                Remove-Item -LiteralPath $serverRoot -Recurse -Force
            }
            $temporaryRemoved = -not (Test-Path -LiteralPath $serverRoot)
        } catch {
            if ($null -eq $cleanupFailure) { $cleanupFailure = 'VULCAN_ENABLEMENT_TEMPORARY_MATERIAL_CLEANUP_FAILED' }
        }
        try {
            $remapAfterCleanup = Get-RemapState @($lockedVulcan.path, $lockedPaper.path, $lockedMCAce.path)
            if ($remapAfterCleanup.manifest_sha256 -cne $remapBefore.manifest_sha256 -or
                    $remapAfterCleanup.file_count -ne $remapBefore.file_count) {
                throw 'VULCAN_ENABLEMENT_ORIGINAL_ARTIFACT_PARENT_REMAP_CHANGED'
            }
        } catch {
            if ($null -eq $cleanupFailure) { $cleanupFailure = $_.Exception.Message }
        }
        if ($null -ne $cleanupFailure) { throw $cleanupFailure }
    }
    if (-not $passed -or $remaining -ne 0 -or -not $temporaryRemoved) {
        throw 'VULCAN_ENABLEMENT_FAILED_OR_CLEANUP_INCOMPLETE'
    }
    $preparedAfter = Assert-PreparedAssets $preparedBinding.path $expectedPrepared
    if ($preparedAfter.manifest_sha256 -cne $preparedBinding.manifest_sha256 -or
            $preparedAfter.file_count -ne $preparedBinding.file_count) {
        throw 'VULCAN_ENABLEMENT_PREPARED_CACHE_CHANGED_DURING_RUN'
    }
    $report = [ordered]@{
        schema = $reportSchema; generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        source_mode = 'EXECUTED_OPERATOR_NETWORK_ATTESTED'; plugin_name = 'Vulcan'; plugin_version = '2.9.0'
        vulcan_sha256 = $expectedVulcan; paper_sha256 = $expectedPaper; mcace_sha256 = $expectedMCAce
        vulcan_size = [long]$lockedVulcan.length; paper_size = [long]$lockedPaper.length
        mcace_size = [long]$lockedMCAce.length; network_policy = 'DENY_ALL_OPERATOR_ATTESTATION'
        network_isolation_operator_attested = $true; network_isolation_os_verified_by_script = $false
        paper_process_coverage = $true; licensed_plugin_enablement_coverage = $true
        mcace_listener_registration_coverage = $true; real_behavior_event_delivery_coverage = $false
        temporary_paper_remap_allowed = $true; temporary_material_removed = $true
        remaining_marker_process_count = 0
        limitations = @('ENABLEMENT_AND_LISTENER_REGISTRATION_ONLY',
            'REAL_BEHAVIOR_EVENT_DELIVERY_NOT_COVERED',
            'NETWORK_ISOLATION_OPERATOR_ATTESTED_NOT_OS_VERIFIED_BY_SCRIPT')
        passed = $true
    }
    $reportRaw = $report | ConvertTo-Json -Depth 6
    $reportBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($reportRaw)
    $reportPath = Join-Path $runRoot 'report.json'
    [System.IO.File]::WriteAllBytes($reportPath, $reportBytes)
    $binding = [ordered]@{
        schema = $bindingSchema; report_schema = $reportSchema; report_generated_at = $report.generated_at
        report_sha256 = Get-BytesSha256 $reportBytes; source_mode = 'EXECUTED_OPERATOR_NETWORK_ATTESTED'
        vulcan_sha256 = $expectedVulcan; paper_sha256 = $expectedPaper; mcace_sha256 = $expectedMCAce
        wrapper_sha256 = $currentBinding.wrapper_sha256; source_manifest_sha256 = $currentBinding.source_manifest_sha256
        source_file_count = $currentBinding.source_file_count; java_executable_sha256 = $currentBinding.java_executable_sha256
        java_file_version = $currentBinding.java_file_version
        prepared_manifest_sha256 = $preparedBinding.manifest_sha256; prepared_file_count = $preparedBinding.file_count
        passed = $true
    }
    [System.IO.File]::WriteAllText((Join-Path $runRoot 'binding.json'),
        ($binding | ConvertTo-Json -Depth 4), [System.Text.UTF8Encoding]::new($false))
    $null = Assert-EvidencePair $reportPath $expectedVulcan $expectedPaper $expectedMCAce $expectedPrepared
    Write-Output 'VULCAN_PAPER_ENABLEMENT_PASS|sanitized-report-retained'
} finally {
    if ($null -ne $lockedMCAce) { $lockedMCAce.stream.Dispose() }
    if ($null -ne $lockedPaper) { $lockedPaper.stream.Dispose() }
    if ($null -ne $lockedVulcan) { $lockedVulcan.stream.Dispose() }
}
