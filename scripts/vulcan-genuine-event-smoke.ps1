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
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [ValidateSet('DenyAll')] [string]$NetworkPolicy,
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [switch]$NetworkIsolationAttested,
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [switch]$GenuineExternalTriggerAttested,
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [switch]$NoSyntheticEventInjectionAttested,
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [string]$ExpectedPlayerUuid,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [ValidateRange(1024, 65535)] [int]$PaperListenPort,
    [ValidateRange(30, 900)] [int]$HumanTriggerTimeoutSeconds = 300,
    [ValidateRange(1, 1440)] [int]$MaximumReportAgeMinutes = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runsRoot = Join-Path $repoRoot 'build\vulcan-genuine-event\runs'
$wrapperPath = Join-Path $PSScriptRoot 'vulcan-genuine-event-smoke.ps1'
$reportSchema = 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_V1'
$bindingSchema = 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_BINDING_V1'
$reviewedVulcanSha256 = '7ee3a4fdd7e9da5269f9efc327478e507563e6e7df7abec2222acd3b499bc993'
$expectedPluginVersion = '2.9.0'
$serverId = 'vulcan-genuine-event-gate'

function ConvertTo-Sha256([string]$Value, [string]$Field) {
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "VULCAN_GENUINE_EVENT_INVALID_SHA256: $Field"
    }
    $normalized = $Value.Trim().ToLowerInvariant()
    if ($normalized -notmatch '^[0-9a-f]{64}$') {
        throw "VULCAN_GENUINE_EVENT_INVALID_SHA256: $Field"
    }
    return $normalized
}

function ConvertTo-ExpectedUuid([string]$Value) {
    $parsed = [guid]::Empty
    if ([string]::IsNullOrWhiteSpace($Value) -or
            -not [guid]::TryParseExact($Value.Trim(), 'D', [ref]$parsed) -or
            $parsed -eq [guid]::Empty) {
        throw 'VULCAN_GENUINE_EVENT_EXPECTED_PLAYER_UUID_INVALID'
    }
    return $parsed.ToString('D').ToLowerInvariant()
}

function Assert-ExpectedPreparedManifest([string]$Actual, [string]$Expected) {
    if ($Actual -cne $Expected) {
        throw 'VULCAN_GENUINE_EVENT_PREPARED_MANIFEST_HASH_MISMATCH'
    }
}

function Get-BytesSha256([byte[]]$Bytes) {
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
}

function Assert-DirectLocalPath([string]$Path, [switch]$Directory) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('"') -or
            -not [System.IO.Path]::IsPathRooted($Path) -or $Path -notmatch '^[A-Za-z]:[\\/]') {
        throw 'VULCAN_GENUINE_EVENT_ABSOLUTE_LOCAL_PATH_REQUIRED'
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    $drive = [System.IO.DriveInfo]::new($root)
    if ($drive.DriveType -ne [System.IO.DriveType]::Fixed) {
        throw 'VULCAN_GENUINE_EVENT_FIXED_LOCAL_DRIVE_REQUIRED'
    }
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($Directory -and -not $item.PSIsContainer) {
        throw 'VULCAN_GENUINE_EVENT_DIRECTORY_REQUIRED'
    }
    if (-not $Directory -and $item.PSIsContainer) {
        throw 'VULCAN_GENUINE_EVENT_FILE_REQUIRED'
    }
    $cursorPath = $item.FullName
    while (-not [string]::IsNullOrWhiteSpace($cursorPath)) {
        $cursor = Get-Item -LiteralPath $cursorPath -Force -ErrorAction Stop
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'VULCAN_GENUINE_EVENT_REPARSE_PATH_REJECTED'
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
        throw 'VULCAN_GENUINE_EVENT_PATH_ESCAPED_ISOLATED_ROOT'
    }
    return $resolvedPath
}

function Get-PathBinding([string]$Path) {
    $resolved = Assert-DirectLocalPath $Path
    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $sha = ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        } finally {
            $hasher.Dispose()
        }
        return [pscustomobject]@{ path = $resolved; length = [long]$stream.Length; sha256 = $sha }
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Open-LockedJar([string]$Path, [string]$ExpectedSha256) {
    $resolved = Assert-DirectLocalPath $Path
    if ([System.IO.Path]::GetExtension($resolved) -cne '.jar') {
        throw 'VULCAN_GENUINE_EVENT_JAR_REQUIRED'
    }
    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($stream.Length -le 0) { throw 'VULCAN_GENUINE_EVENT_EMPTY_ARTIFACT' }
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $actual = ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        } finally {
            $hasher.Dispose()
        }
        $stream.Position = 0
        if ($actual -cne $ExpectedSha256) {
            throw 'VULCAN_GENUINE_EVENT_ARTIFACT_HASH_MISMATCH'
        }
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
        if ($null -eq $firstFile) { throw 'VULCAN_GENUINE_EVENT_PREPARED_CACHE_INCOMPLETE' }
    }
    $entries = @()
    foreach ($entry in Get-ChildItem -LiteralPath $resolved -Recurse -Force) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'VULCAN_GENUINE_EVENT_PREPARED_CACHE_REPARSE_REJECTED'
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
    if ($ordered.Count -eq 0) { throw 'VULCAN_GENUINE_EVENT_PREPARED_CACHE_INCOMPLETE' }
    $manifest = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes(($ordered -join "`n")))
    Assert-ExpectedPreparedManifest $manifest $ExpectedManifestSha256
    return [pscustomobject]@{
        path = $resolved
        manifest_sha256 = $manifest
        file_count = [int]$ordered.Count
    }
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
    if ([string]::IsNullOrWhiteSpace($env:JAVA_HOME)) {
        throw 'VULCAN_GENUINE_EVENT_JAVA_HOME_21_REQUIRED'
    }
    $java = Get-PathBinding (Join-Path $env:JAVA_HOME 'bin\java.exe')
    $version = [string](Get-Item -LiteralPath $java.path).VersionInfo.FileVersion
    if ($version -notmatch '^21(?:\.|$)') {
        throw 'VULCAN_GENUINE_EVENT_JAVA_HOME_21_REQUIRED'
    }
    $sources = [ordered]@{
        paper_plugin = 'mcace-server-paper/src/main/java/com/ellan/mcace/paper/MCAcePaperPlugin.java'
        integration_config = 'mcace-server-paper/src/main/java/com/ellan/mcace/paper/PaperIntegrationConfiguration.java'
        behavior_alert = 'mcace-server-paper/src/main/java/com/ellan/mcace/paper/behavior/BehaviorAlert.java'
        behavior_pipeline = 'mcace-server-paper/src/main/java/com/ellan/mcace/paper/behavior/BehaviorAlertPipeline.java'
        behavior_correlator = 'mcace-server-paper/src/main/java/com/ellan/mcace/paper/behavior/BehaviorAlertCorrelator.java'
        vulcan_integration = 'mcace-server-paper/src/main/java/com/ellan/mcace/paper/behavior/VulcanBehaviorIntegration.java'
        vulcan_contract = 'mcace-server-paper/src/main/java/com/ellan/mcace/paper/behavior/VulcanApiCompatibility.java'
        cloud_client = 'mcace-cloud-client/src/main/java/com/ellan/mcace/cloudclient/CloudRiskEventClient.java'
        cloud_config = 'mcace-cloud-client/src/main/java/com/ellan/mcace/cloudclient/CloudClientConfiguration.java'
        default_config = 'mcace-server-paper/src/main/resources/config.yml'
        plugin_metadata = 'mcace-server-paper/src/main/resources/plugin.yml'
    }
    $entries = foreach ($entry in $sources.GetEnumerator()) {
        $file = Get-PathBinding (Join-Path $repoRoot $entry.Value)
        "$($entry.Key)|$($file.length)|$($file.sha256)"
    }
    $manifest = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes(($entries -join "`n")))
    $wrapper = Get-PathBinding $wrapperPath
    return [pscustomobject]@{
        wrapper_sha256 = $wrapper.sha256
        source_manifest_sha256 = $manifest
        source_file_count = [int]$sources.Count
        java_path = $java.path
        java_executable_sha256 = $java.sha256
        java_file_version = $version
    }
}

function New-LoopbackObserver {
    $listener = [System.Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $endpoint = [Net.IPEndPoint]$listener.LocalEndpoint
    $challengeId = [guid]::NewGuid().ToString('N')
    $token = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
    $payload = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($payload)
    $encodedPayload = [Convert]::ToBase64String($payload).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    return [pscustomobject]@{
        listener = $listener
        port = [int]$endpoint.Port
        accept_task = $listener.AcceptTcpClientAsync()
        challenge_id = $challengeId
        signing_payload = $encodedPayload
        access_token = $token
        challenge_issued = $false
        token_issued = $false
        invalid_request_count = 0
        total_risk_event_count = 0
        matching_events = [System.Collections.Generic.List[object]]::new()
    }
}

function Read-ObserverRequest([Net.Sockets.TcpClient]$Client) {
    $Client.ReceiveTimeout = 5000
    $Client.SendTimeout = 5000
    $stream = $Client.GetStream()
    $buffer = [System.Collections.Generic.List[byte]]::new()
    $headerEnd = -1
    while ($buffer.Count -lt 16384 -and $headerEnd -lt 0) {
        $value = $stream.ReadByte()
        if ($value -lt 0) { break }
        $buffer.Add([byte]$value)
        $count = $buffer.Count
        if ($count -ge 4 -and $buffer[$count - 4] -eq 13 -and $buffer[$count - 3] -eq 10 -and
                $buffer[$count - 2] -eq 13 -and $buffer[$count - 1] -eq 10) {
            $headerEnd = $count
        }
    }
    if ($headerEnd -lt 0) { throw 'VULCAN_GENUINE_EVENT_OBSERVER_HTTP_HEADER_INVALID' }
    $headerBytes = $buffer.ToArray()
    $headerText = [Text.Encoding]::ASCII.GetString($headerBytes, 0, $headerEnd - 4)
    $lines = @($headerText -split "`r`n")
    if ($lines.Count -lt 1 -or $lines[0] -notmatch '^POST ([^ ]+) HTTP/1\.[01]$') {
        throw 'VULCAN_GENUINE_EVENT_OBSERVER_HTTP_REQUEST_LINE_INVALID'
    }
    $path = $Matches[1]
    $headers = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in @($lines | Select-Object -Skip 1)) {
        $colon = $line.IndexOf(':')
        if ($colon -lt 1) { throw 'VULCAN_GENUINE_EVENT_OBSERVER_HTTP_HEADER_INVALID' }
        $name = $line.Substring(0, $colon).Trim()
        $value = $line.Substring($colon + 1).Trim()
        if ($headers.ContainsKey($name)) { throw 'VULCAN_GENUINE_EVENT_OBSERVER_DUPLICATE_HEADER' }
        $headers.Add($name, $value)
    }
    if (-not $headers.ContainsKey('Content-Length')) {
        throw 'VULCAN_GENUINE_EVENT_OBSERVER_CONTENT_LENGTH_REQUIRED'
    }
    $contentLength = 0
    if (-not [int]::TryParse($headers['Content-Length'], [ref]$contentLength) -or
            $contentLength -lt 0 -or $contentLength -gt 65536) {
        throw 'VULCAN_GENUINE_EVENT_OBSERVER_CONTENT_LENGTH_INVALID'
    }
    $body = New-Object byte[] $contentLength
    $offset = 0
    while ($offset -lt $contentLength) {
        $read = $stream.Read($body, $offset, $contentLength - $offset)
        if ($read -le 0) { throw 'VULCAN_GENUINE_EVENT_OBSERVER_BODY_TRUNCATED' }
        $offset += $read
    }
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    $rawBody = $encoding.GetString($body)
    return [pscustomobject]@{ path = $path; headers = $headers; body = $rawBody; stream = $stream }
}

function Write-ObserverResponse([IO.Stream]$Stream, [int]$StatusCode, [string]$Body) {
    $reason = switch ($StatusCode) {
        201 { 'Created' }
        202 { 'Accepted' }
        400 { 'Bad Request' }
        401 { 'Unauthorized' }
        404 { 'Not Found' }
        default { 'Error' }
    }
    $bodyBytes = [Text.UTF8Encoding]::new($false).GetBytes($Body)
    $headers = "HTTP/1.1 $StatusCode $reason`r`nContent-Type: application/json`r`n" +
        "Content-Length: $($bodyBytes.Length)`r`nConnection: close`r`n`r`n"
    $headerBytes = [Text.Encoding]::ASCII.GetBytes($headers)
    $Stream.Write($headerBytes, 0, $headerBytes.Length)
    $Stream.Write($bodyBytes, 0, $bodyBytes.Length)
    $Stream.Flush()
}

function Test-JsonString([object]$Value) {
    return $Value -is [string]
}

function Test-JsonBoolean([object]$Value) {
    return $Value -is [bool]
}

function Test-JsonInteger([object]$Value) {
    return $Value -is [byte] -or $Value -is [int16] -or
        $Value -is [int32] -or $Value -is [int64]
}

function Get-JsonPropertyNames([object]$Value) {
    return @($Value.PSObject.Properties | ForEach-Object Name)
}

function Test-ExactProperties([object]$Value, [string[]]$Expected) {
    $actual = @(Get-JsonPropertyNames $Value | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    return $actual.Count -eq $wanted.Count -and (($actual -join "`n") -ceq ($wanted -join "`n"))
}

function Test-GenuineRiskPayload(
        [object]$Payload, [string]$ExpectedUuid, [string]$ExpectedVersion) {
    $topLevel = @('event_id', 'player_uuid', 'type', 'source_component', 'origin',
        'corroborated', 'observed_at', 'details')
    if (-not (Test-ExactProperties $Payload $topLevel)) { return $null }
    foreach ($name in @('event_id', 'player_uuid', 'type', 'source_component', 'origin', 'observed_at')) {
        if (-not (Test-JsonString $Payload.$name)) { return $null }
    }
    if (-not (Test-JsonBoolean $Payload.corroborated)) { return $null }
    $eventId = [guid]::Empty
    $playerId = [guid]::Empty
    if (-not [guid]::TryParseExact($Payload.event_id, 'D', [ref]$eventId) -or
            -not [guid]::TryParseExact($Payload.player_uuid, 'D', [ref]$playerId)) {
        return $null
    }
    $observedAt = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($Payload.observed_at, [ref]$observedAt)) { return $null }
    $details = $Payload.details
    if ($null -eq $details) { return $null }
    $detailNames = @('schema', 'provider', 'provider_version', 'check', 'stable_check',
        'flag_count', 'window_ms', 'first_observed_at', 'maximum_violation_level',
        'experimental', 'independent_providers')
    if (-not (Test-ExactProperties $details $detailNames)) { return $null }
    foreach ($name in @('schema', 'provider', 'provider_version', 'check', 'stable_check', 'first_observed_at')) {
        if (-not (Test-JsonString $details.$name)) { return $null }
    }
    if (-not (Test-JsonInteger $details.flag_count) -or -not (Test-JsonInteger $details.window_ms) -or
            -not (Test-JsonBoolean $details.experimental)) {
        return $null
    }
    $maximumViolation = 0.0D
    if (-not [double]::TryParse(
            [string]$details.maximum_violation_level,
            [Globalization.NumberStyles]::Float,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$maximumViolation) -or [double]::IsNaN($maximumViolation) -or
            [double]::IsInfinity($maximumViolation) -or
            $maximumViolation -lt 0.0D) {
        return $null
    }
    $firstObserved = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($details.first_observed_at, [ref]$firstObserved)) { return $null }
    $providers = @($details.independent_providers)
    if ($Payload.player_uuid.ToLowerInvariant() -cne $ExpectedUuid -or
            $Payload.type -cne 'BEHAVIOR_HIGH_RISK' -or
            $Payload.source_component -cne 'vulcan-adapter' -or
            $Payload.origin -cne 'SERVER_CONFIRMED' -or $Payload.corroborated -or
            $details.schema -cne 'mcace.behavior-alert.v1' -or
            $details.provider -cne 'vulcan' -or $details.provider_version -cne $ExpectedVersion -or
            [string]::IsNullOrWhiteSpace($details.check) -or
            [string]::IsNullOrWhiteSpace($details.stable_check) -or
            [int64]$details.flag_count -lt 1 -or [int64]$details.window_ms -lt 1 -or
            $details.experimental -or $providers.Count -ne 1 -or $providers[0] -cne 'vulcan') {
        return $null
    }
    return [pscustomobject]@{
        flag_count = [int64]$details.flag_count
        check_nonempty = $true
        stable_check_nonempty = $true
    }
}

function Invoke-ObserverRequest(
        [object]$Observer, [Net.Sockets.TcpClient]$Client,
        [string]$ExpectedUuid, [string]$ExpectedVersion) {
    try {
        $request = Read-ObserverRequest $Client
        $json = $null
        try { $json = $request.body | ConvertFrom-Json -ErrorAction Stop } catch {
            $Observer.invalid_request_count++
            Write-ObserverResponse $request.stream 400 '{"error":"invalid_json"}'
            return
        }
        if ($request.path -ceq '/v1/auth/challenges') {
            if (-not (Test-ExactProperties $json @('server_id')) -or
                    -not (Test-JsonString $json.server_id) -or $json.server_id -cne $serverId) {
                $Observer.invalid_request_count++
                Write-ObserverResponse $request.stream 400 '{"error":"invalid_challenge"}'
                return
            }
            $Observer.challenge_issued = $true
            $body = [ordered]@{
                challenge_id = $Observer.challenge_id
                signing_payload = $Observer.signing_payload
            } | ConvertTo-Json -Compress
            Write-ObserverResponse $request.stream 201 $body
            return
        }
        if ($request.path -ceq '/v1/auth/tokens') {
            if (-not $Observer.challenge_issued -or
                    -not (Test-ExactProperties $json @('challenge_id', 'server_id', 'signature')) -or
                    -not (Test-JsonString $json.challenge_id) -or
                    -not (Test-JsonString $json.server_id) -or
                    -not (Test-JsonString $json.signature) -or
                    $json.challenge_id -cne $Observer.challenge_id -or
                    $json.server_id -cne $serverId -or [string]::IsNullOrWhiteSpace($json.signature)) {
                $Observer.invalid_request_count++
                Write-ObserverResponse $request.stream 400 '{"error":"invalid_token_request"}'
                return
            }
            $Observer.token_issued = $true
            $body = [ordered]@{
                access_token = $Observer.access_token
                expires_at = [DateTimeOffset]::UtcNow.AddMinutes(5).ToString('o')
            } | ConvertTo-Json -Compress
            Write-ObserverResponse $request.stream 201 $body
            return
        }
        if ($request.path -ceq '/v1/risk-events') {
            $authorized = $Observer.token_issued -and
                $request.headers.ContainsKey('Authorization') -and
                $request.headers['Authorization'] -ceq ('Bearer ' + $Observer.access_token)
            if (-not $authorized) {
                $Observer.invalid_request_count++
                Write-ObserverResponse $request.stream 401 '{"error":"unauthorized"}'
                return
            }
            $Observer.total_risk_event_count++
            $matched = Test-GenuineRiskPayload $json $ExpectedUuid $ExpectedVersion
            if ($null -ne $matched) { $Observer.matching_events.Add($matched) }
            Write-ObserverResponse $request.stream 202 '{"enforcement_action":"NONE"}'
            return
        }
        $Observer.invalid_request_count++
        Write-ObserverResponse $request.stream 404 '{"error":"not_found"}'
    } catch {
        $Observer.invalid_request_count++
        try {
            if ($Client.Connected) {
                Write-ObserverResponse $Client.GetStream() 400 '{"error":"invalid_request"}'
            }
        } catch { }
    } finally {
        $Client.Dispose()
    }
}

function Receive-ObserverRequests(
        [object]$Observer, [string]$ExpectedUuid, [string]$ExpectedVersion) {
    while ($Observer.accept_task.IsCompleted) {
        $client = $Observer.accept_task.GetAwaiter().GetResult()
        $Observer.accept_task = $Observer.listener.AcceptTcpClientAsync()
        Invoke-ObserverRequest $Observer $client $ExpectedUuid $ExpectedVersion
    }
}

function Stop-LoopbackObserver([object]$Observer) {
    if ($null -ne $Observer -and $null -ne $Observer.listener) {
        $Observer.listener.Stop()
    }
}

function Write-ServerConfiguration(
        [string]$ServerRoot, [int]$PaperPort, [int]$ObserverPort, [string]$PreparedRoot) {
    foreach ($directory in @('cache', 'libraries', 'versions')) {
        Copy-Item -LiteralPath (Join-Path $PreparedRoot $directory) `
            -Destination (Join-Path $ServerRoot $directory) -Recurse -Force
    }
    $data = Join-Path $ServerRoot 'plugins\MCAce'
    $bstats = Join-Path $ServerRoot 'plugins\bStats'
    New-Item -ItemType Directory -Force -Path $data, $bstats | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $ServerRoot 'eula.txt'), "eula=true`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $ServerRoot 'server.properties'),
        "online-mode=false`nenforce-secure-profile=false`nserver-ip=127.0.0.1`nserver-port=$PaperPort`n" +
        "enable-query=false`nspawn-protection=0`nview-distance=4`nsimulation-distance=4`n" +
        "motd=MCAce licensed Vulcan genuine event gate`n",
        [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText(
        (Join-Path $bstats 'config.yml'), "enabled: false`n", [Text.UTF8Encoding]::new($false))
    # Public RFC 8032 test-vector material; it is not a production identity or secret.
    [IO.File]::WriteAllText((Join-Path $data 'proxy-public-key.txt'),
        "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=`n",
        [Text.Encoding]::ASCII)
    [IO.File]::WriteAllBytes((Join-Path $data 'cloud-server-private-key.pk8'),
        [Convert]::FromBase64String('MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g'))
    $configuration = @"
session-actions:
  mode: MONITOR
behavior:
  enabled: true
  minimum-flags: 1
  window-seconds: 10
  cooldown-seconds: 3600
  maximum-tracked-keys: 32
  grim:
    enabled: false
  vulcan:
    enabled: true
cloud:
  enabled: true
  endpoint: "http://127.0.0.1:$ObserverPort"
  server-id: "$serverId"
  private-key-path: "cloud-server-private-key.pk8"
  queue-capacity: 8
  request-timeout-ms: 2000
"@
    [IO.File]::WriteAllText(
        (Join-Path $data 'config.yml'), $configuration, [Text.UTF8Encoding]::new($false))
}

function ConvertTo-ProcessArgument([string]$Value) {
    if ($Value.Contains('"')) { throw 'VULCAN_GENUINE_EVENT_PROCESS_ARGUMENT_INVALID' }
    return '"' + $Value + '"'
}

function Get-MarkerProcesses([string]$Marker) {
    return @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.CommandLine) -and
        ([string]$_.CommandLine).IndexOf($Marker, [StringComparison]::Ordinal) -ge 0
    })
}

function Test-OwnedProcess(
        [Diagnostics.Process]$Process, [int]$ExpectedId,
        [datetime]$ExpectedStartTimeUtc, [string]$Marker) {
    if ($null -eq $Process -or $Process.HasExited -or $Process.Id -ne $ExpectedId) { return $false }
    $Process.Refresh()
    if ($Process.StartTime.ToUniversalTime() -ne $ExpectedStartTimeUtc) { return $false }
    $records = @(Get-CimInstance -ClassName Win32_Process `
        -Filter "ProcessId = $ExpectedId" -ErrorAction Stop)
    return $records.Count -eq 1 -and
        ([string]$records[0].CommandLine).IndexOf($Marker, [StringComparison]::Ordinal) -ge 0
}

function Stop-OwnedProcess(
        [Diagnostics.Process]$Process, [int]$ExpectedId,
        [datetime]$ExpectedStartTimeUtc, [string]$Marker) {
    if ($Process.HasExited) { return }
    if (-not (Test-OwnedProcess $Process $ExpectedId $ExpectedStartTimeUtc $Marker)) {
        throw 'VULCAN_GENUINE_EVENT_PROCESS_OWNERSHIP_UNPROVEN'
    }
    $treeKill = [Diagnostics.Process].GetMethods() | Where-Object {
        $_.Name -eq 'Kill' -and $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType -eq [bool]
    } | Select-Object -First 1
    if ($null -ne $treeKill) { [void]$treeKill.Invoke($Process, @($true)) }
    else { $Process.Kill() }
    if (-not $Process.WaitForExit(30000)) {
        throw 'VULCAN_GENUINE_EVENT_PROCESS_DID_NOT_EXIT'
    }
}

function Assert-SanitizedEvidence([string]$Raw) {
    if ($Raw.Length -gt 32768 -or
            $Raw -match '(?i)[A-Z]:[\/]|\\\\|(?:^|["\s])/(?:home|users|tmp|var|opt|mnt|root)/' -or
            $Raw -match '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b' -or
            $Raw -match '(?i)"(?:pid|port|player_uuid|event_id|check|stable_check)"\s*:') {
        throw 'VULCAN_GENUINE_EVENT_EVIDENCE_NOT_SANITIZED'
    }
}

function Open-LockedEvidence([string]$Path) {
    $resolved = Assert-DirectLocalPath $Path
    $stream = $null
    try {
        $stream = [IO.File]::Open(
            $resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($stream.Length -le 0 -or $stream.Length -gt 32768) {
            throw 'VULCAN_GENUINE_EVENT_EVIDENCE_SIZE_INVALID'
        }
        $memory = [IO.MemoryStream]::new()
        try {
            $stream.CopyTo($memory)
            $bytes = $memory.ToArray()
        } finally {
            $memory.Dispose()
        }
        $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        Assert-SanitizedEvidence $raw
        return [pscustomobject]@{
            raw = $raw
            sha256 = Get-BytesSha256 $bytes
            stream = $stream
        }
    } catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}

function Assert-ReportRaw(
        [string]$Raw, [string]$ExpectedVulcan,
        [string]$ExpectedPaper, [string]$ExpectedMCAce) {
    $names = @(
        'schema', 'generated_at', 'source_mode',
        'vulcan_sha256', 'paper_sha256', 'mcace_sha256',
        'vulcan_size', 'paper_size', 'mcace_size',
        'plugin_name', 'plugin_version', 'provider', 'provider_version',
        'event_type', 'source_component', 'origin',
        'network_policy', 'network_isolation_operator_attested',
        'network_isolation_os_verified_by_script',
        'genuine_external_trigger_operator_attested',
        'no_synthetic_event_injection_operator_attested',
        'gate_invoked_plugin_manager_call_event', 'gate_used_test_fixture',
        'gate_used_vendor_synthetic_event',
        'paper_process_coverage', 'licensed_plugin_enablement_coverage',
        'mcace_listener_registration_coverage', 'mcace_adapter_extraction_coverage',
        'mcace_correlator_coverage', 'mcace_queue_auth_delivery_coverage',
        'real_behavior_event_delivery_coverage', 'expected_player_matched',
        'unique_matching_event_count', 'total_risk_event_count',
        'check_nonempty', 'stable_check_nonempty', 'flag_count',
        'temporary_paper_remap_allowed', 'temporary_material_removed',
        'remaining_marker_process_count', 'limitations', 'passed')
    try { $report = $Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'VULCAN_GENUINE_EVENT_REPORT_JSON_INVALID' }
    if (-not (Test-ExactProperties $report $names)) {
        throw 'VULCAN_GENUINE_EVENT_REPORT_PROPERTIES_INVALID'
    }
    foreach ($name in @('schema', 'generated_at', 'source_mode', 'vulcan_sha256',
            'paper_sha256', 'mcace_sha256', 'plugin_name', 'plugin_version', 'provider',
            'provider_version', 'event_type', 'source_component', 'origin', 'network_policy')) {
        if (-not (Test-JsonString $report.$name)) {
            throw 'VULCAN_GENUINE_EVENT_REPORT_TYPE_INVALID'
        }
    }
    foreach ($name in @('network_isolation_operator_attested',
            'network_isolation_os_verified_by_script',
            'genuine_external_trigger_operator_attested',
            'no_synthetic_event_injection_operator_attested',
            'gate_invoked_plugin_manager_call_event', 'gate_used_test_fixture',
            'gate_used_vendor_synthetic_event', 'paper_process_coverage',
            'licensed_plugin_enablement_coverage', 'mcace_listener_registration_coverage',
            'mcace_adapter_extraction_coverage', 'mcace_correlator_coverage',
            'mcace_queue_auth_delivery_coverage', 'real_behavior_event_delivery_coverage',
            'expected_player_matched', 'check_nonempty', 'stable_check_nonempty',
            'temporary_paper_remap_allowed', 'temporary_material_removed', 'passed')) {
        if (-not (Test-JsonBoolean $report.$name)) {
            throw 'VULCAN_GENUINE_EVENT_REPORT_TYPE_INVALID'
        }
    }
    foreach ($name in @('vulcan_size', 'paper_size', 'mcace_size',
            'unique_matching_event_count', 'total_risk_event_count', 'flag_count',
            'remaining_marker_process_count')) {
        if (-not (Test-JsonInteger $report.$name)) {
            throw 'VULCAN_GENUINE_EVENT_REPORT_TYPE_INVALID'
        }
    }
    $timestamp = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            $report.generated_at, 'o', [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None, [ref]$timestamp)) {
        throw 'VULCAN_GENUINE_EVENT_REPORT_TIMESTAMP_INVALID'
    }
    $age = [DateTimeOffset]::UtcNow - $timestamp
    if ($age.TotalMinutes -lt 0 -or $age.TotalMinutes -gt $MaximumReportAgeMinutes) {
        throw 'VULCAN_GENUINE_EVENT_REPORT_STALE'
    }
    $limitations = @($report.limitations)
    if ($limitations.Count -ne 2 -or
            $limitations[0] -cne 'HUMAN_TRIGGER_ORIGIN_OPERATOR_ATTESTED_NOT_OS_OR_VENDOR_VERIFIED_BY_SCRIPT' -or
            $limitations[1] -cne 'NETWORK_ISOLATION_OPERATOR_ATTESTED_NOT_OS_VERIFIED_BY_SCRIPT') {
        throw 'VULCAN_GENUINE_EVENT_REPORT_LIMITATIONS_INVALID'
    }
    if ($report.schema -cne $reportSchema -or
            $report.source_mode -cne 'EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED' -or
            $report.vulcan_sha256 -cne $ExpectedVulcan -or
            $report.paper_sha256 -cne $ExpectedPaper -or
            $report.mcace_sha256 -cne $ExpectedMCAce -or
            $report.vulcan_size -le 0 -or $report.paper_size -le 0 -or $report.mcace_size -le 0 -or
            $report.plugin_name -cne 'Vulcan' -or $report.plugin_version -cne $expectedPluginVersion -or
            $report.provider -cne 'vulcan' -or $report.provider_version -cne $expectedPluginVersion -or
            $report.event_type -cne 'BEHAVIOR_HIGH_RISK' -or
            $report.source_component -cne 'vulcan-adapter' -or $report.origin -cne 'SERVER_CONFIRMED' -or
            $report.network_policy -cne 'DENY_ALL_OPERATOR_ATTESTATION' -or
            -not $report.network_isolation_operator_attested -or
            $report.network_isolation_os_verified_by_script -or
            -not $report.genuine_external_trigger_operator_attested -or
            -not $report.no_synthetic_event_injection_operator_attested -or
            $report.gate_invoked_plugin_manager_call_event -or $report.gate_used_test_fixture -or
            $report.gate_used_vendor_synthetic_event -or -not $report.paper_process_coverage -or
            -not $report.licensed_plugin_enablement_coverage -or
            -not $report.mcace_listener_registration_coverage -or
            -not $report.mcace_adapter_extraction_coverage -or
            -not $report.mcace_correlator_coverage -or
            -not $report.mcace_queue_auth_delivery_coverage -or
            -not $report.real_behavior_event_delivery_coverage -or
            -not $report.expected_player_matched -or
            $report.unique_matching_event_count -ne 1 -or $report.total_risk_event_count -ne 1 -or
            -not $report.check_nonempty -or -not $report.stable_check_nonempty -or
            $report.flag_count -lt 1 -or -not $report.temporary_paper_remap_allowed -or
            -not $report.temporary_material_removed -or
            $report.remaining_marker_process_count -ne 0 -or -not $report.passed) {
        throw 'VULCAN_GENUINE_EVENT_REPORT_INVALID'
    }
    return $report
}

function Assert-BindingRaw(
        [string]$Raw, [string]$ExpectedReportSha256, [object]$Report,
        [string]$ExpectedVulcan, [string]$ExpectedPaper,
        [string]$ExpectedMCAce, [string]$ExpectedPrepared) {
    $names = @('schema', 'report_schema', 'report_generated_at', 'report_sha256',
        'source_mode', 'vulcan_sha256', 'paper_sha256', 'mcace_sha256',
        'wrapper_sha256', 'source_manifest_sha256', 'source_file_count',
        'java_executable_sha256', 'java_file_version',
        'prepared_manifest_sha256', 'prepared_file_count', 'passed')
    try { $binding = $Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'VULCAN_GENUINE_EVENT_BINDING_JSON_INVALID' }
    if (-not (Test-ExactProperties $binding $names)) {
        throw 'VULCAN_GENUINE_EVENT_BINDING_PROPERTIES_INVALID'
    }
    foreach ($name in @('schema', 'report_schema', 'report_generated_at', 'report_sha256',
            'source_mode', 'vulcan_sha256', 'paper_sha256', 'mcace_sha256',
            'wrapper_sha256', 'source_manifest_sha256', 'java_executable_sha256',
            'java_file_version', 'prepared_manifest_sha256')) {
        if (-not (Test-JsonString $binding.$name)) {
            throw 'VULCAN_GENUINE_EVENT_BINDING_TYPE_INVALID'
        }
    }
    if (-not (Test-JsonInteger $binding.source_file_count) -or
            -not (Test-JsonInteger $binding.prepared_file_count) -or
            -not (Test-JsonBoolean $binding.passed)) {
        throw 'VULCAN_GENUINE_EVENT_BINDING_TYPE_INVALID'
    }
    $current = Get-CurrentBinding
    if ($binding.schema -cne $bindingSchema -or $binding.report_schema -cne $reportSchema -or
            $binding.report_generated_at -cne $Report.generated_at -or
            $binding.report_sha256 -cne $ExpectedReportSha256 -or
            $binding.source_mode -cne 'EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED' -or
            $binding.vulcan_sha256 -cne $ExpectedVulcan -or
            $binding.paper_sha256 -cne $ExpectedPaper -or
            $binding.mcace_sha256 -cne $ExpectedMCAce -or
            $binding.wrapper_sha256 -cne $current.wrapper_sha256 -or
            $binding.source_manifest_sha256 -cne $current.source_manifest_sha256 -or
            $binding.source_file_count -ne $current.source_file_count -or
            $binding.java_executable_sha256 -cne $current.java_executable_sha256 -or
            $binding.java_file_version -cne $current.java_file_version -or
            $binding.prepared_manifest_sha256 -cne $ExpectedPrepared -or
            $binding.prepared_file_count -le 0 -or -not $binding.passed) {
        throw 'VULCAN_GENUINE_EVENT_BINDING_INVALID'
    }
    Assert-ExpectedPreparedManifest $binding.prepared_manifest_sha256 $ExpectedPrepared
}

function Assert-EvidencePair(
        [string]$ReportPath, [string]$ExpectedVulcan,
        [string]$ExpectedPaper, [string]$ExpectedMCAce, [string]$ExpectedPrepared) {
    $reportEvidence = $null
    $bindingEvidence = $null
    try {
        $reportEvidence = Open-LockedEvidence $ReportPath
        $bindingEvidence = Open-LockedEvidence (Join-Path (Split-Path $ReportPath -Parent) 'binding.json')
        $report = Assert-ReportRaw `
            $reportEvidence.raw $ExpectedVulcan $ExpectedPaper $ExpectedMCAce
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
        Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 } |
        ForEach-Object {
            Get-Item -LiteralPath (Join-Path $_.FullName 'report.json') -ErrorAction SilentlyContinue
        } | Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}

$expectedVulcan = ConvertTo-Sha256 $VulcanSha256 'VulcanSha256'
$expectedPaper = ConvertTo-Sha256 $PaperSha256 'PaperSha256'
$expectedMCAce = ConvertTo-Sha256 $MCAceSha256 'MCAceSha256'
$expectedPrepared = ConvertTo-Sha256 $PreparedManifestSha256 'PreparedManifestSha256'
if ($expectedVulcan -cne $reviewedVulcanSha256) {
    throw 'VULCAN_GENUINE_EVENT_UNREVIEWED_VULCAN_HASH'
}

if ($ReportOnly) {
    foreach ($name in @('VulcanJar', 'PaperJar', 'MCAceJar', 'PreparedRoot',
            'ExpectedPlayerUuid', 'PaperListenPort', 'GenuineExternalTriggerAttested',
            'NoSyntheticEventInjectionAttested')) {
        if ($PSBoundParameters.ContainsKey($name)) {
            throw 'VULCAN_GENUINE_EVENT_REPORT_ONLY_EXECUTION_INPUT_REJECTED'
        }
    }
    $path = Get-LatestReport
    if ($null -eq $path) { throw 'VULCAN_GENUINE_EVENT_REPORT_REQUIRED' }
    $null = Assert-EvidencePair `
        $path $expectedVulcan $expectedPaper $expectedMCAce $expectedPrepared
    Write-Output 'VULCAN_GENUINE_EVENT_PASS|report-only'
    exit 0
}

if (-not $Execute -or -not $AllowTemporaryPaperRemap -or
        $NetworkPolicy -cne 'DenyAll' -or -not $NetworkIsolationAttested -or
        -not $GenuineExternalTriggerAttested -or -not $NoSyntheticEventInjectionAttested) {
    throw 'VULCAN_GENUINE_EVENT_EXPLICIT_EXECUTION_AND_ATTESTATIONS_REQUIRED'
}
$expectedUuid = ConvertTo-ExpectedUuid $ExpectedPlayerUuid

$lockedVulcan = $null
$lockedPaper = $null
$lockedMCAce = $null
$observer = $null
try {
    $lockedVulcan = Open-LockedJar $VulcanJar $expectedVulcan
    $lockedPaper = Open-LockedJar $PaperJar $expectedPaper
    $lockedMCAce = Open-LockedJar $MCAceJar $expectedMCAce
    $preparedBinding = Assert-PreparedAssets $PreparedRoot $expectedPrepared
    $currentBinding = Get-CurrentBinding
    $java = $currentBinding.java_path
    $null = Assert-DirectLocalPath $repoRoot -Directory
    if (-not (Test-Path -LiteralPath $runsRoot)) {
        New-Item -ItemType Directory -Path $runsRoot | Out-Null
    }
    $null = Assert-DirectLocalPath $runsRoot -Directory
    $runToken = [guid]::NewGuid().ToString('N')
    $runRoot = Assert-DescendantPath $runsRoot (Join-Path $runsRoot $runToken)
    $serverRoot = Assert-DescendantPath $runRoot (Join-Path $runRoot 'server')
    New-Item -ItemType Directory -Path $serverRoot | Out-Null
    $processMarker = "mcace-vulcan-genuine-event-$runToken"
    $remapBefore = Get-RemapState @($lockedVulcan.path, $lockedPaper.path, $lockedMCAce.path)
    $process = $null
    $processId = 0
    $processStartTimeUtc = [datetime]::MinValue
    $temporaryRemoved = $false
    $remaining = 0
    $cleanupFailure = $null
    $matched = $null
    try {
        $observer = New-LoopbackObserver
        Write-ServerConfiguration `
            $serverRoot $PaperListenPort $observer.port $preparedBinding.path
        $isolatedPrepared = Assert-PreparedAssets $serverRoot $expectedPrepared
        if ($isolatedPrepared.file_count -ne $preparedBinding.file_count) {
            throw 'VULCAN_GENUINE_EVENT_ISOLATED_PREPARED_COPY_COUNT_MISMATCH'
        }
        $stdout = Join-Path $serverRoot 'paper.stdout.log'
        $stderr = Join-Path $serverRoot 'paper.stderr.log'
        $arguments = @(
            '-Dpaper.disableStartupVersionCheck=true',
            "-Dmcace.vulcan.genuine.event.run=$processMarker",
            '-Xms512m', '-Xmx1024m', '-jar', $lockedPaper.path, '--nogui',
            '--add-plugin', $lockedVulcan.path, '--add-plugin', $lockedMCAce.path)
        $argumentLine = ($arguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' '
        $process = Start-Process -FilePath $java -ArgumentList $argumentLine `
            -WorkingDirectory $serverRoot -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
        $processId = $process.Id
        $processStartTimeUtc = $process.StartTime.ToUniversalTime()
        if (-not (Test-OwnedProcess $process $processId $processStartTimeUtc $processMarker)) {
            throw 'VULCAN_GENUINE_EVENT_STARTED_PROCESS_OWNERSHIP_UNPROVEN'
        }
        $readyDeadline = [DateTime]::UtcNow.AddSeconds(150)
        $vulcanObserved = $false
        $adapterObserved = $false
        $paperReadyObserved = $false
        do {
            Receive-ObserverRequests $observer $expectedUuid $expectedPluginVersion
            Start-Sleep -Milliseconds 250
            $text = ''
            if (Test-Path -LiteralPath $stdout) {
                $text += Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue
            }
            if (Test-Path -LiteralPath $stderr) {
                $text += Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue
            }
            $vulcanObserved = $text -match '(?im)^.*\[Vulcan\] Enabling Vulcan v2\.9\.0\s*$'
            $adapterObserved = $text -match [regex]::Escape(
                'MCAce Vulcan behavior adapter enabled (observational, no automatic punishment)')
            $paperReadyObserved = $text -match '(?im)^.*Done \([0-9.]+s\)! For help, type "help"\s*$'
            if ($process.HasExited -and -not ($vulcanObserved -and $adapterObserved -and $paperReadyObserved)) {
                throw 'VULCAN_GENUINE_EVENT_PAPER_EXITED_EARLY'
            }
        } while (-not ($vulcanObserved -and $adapterObserved -and $paperReadyObserved) -and
            [DateTime]::UtcNow -lt $readyDeadline)
        if (-not ($vulcanObserved -and $adapterObserved -and $paperReadyObserved)) {
            throw 'VULCAN_GENUINE_EVENT_STARTUP_MARKERS_TIMEOUT'
        }
        Write-Output 'VULCAN_GENUINE_EVENT_READY|perform the attested external human behavior now'
        $triggerDeadline = [DateTime]::UtcNow.AddSeconds($HumanTriggerTimeoutSeconds)
        do {
            Receive-ObserverRequests $observer $expectedUuid $expectedPluginVersion
            if ($observer.matching_events.Count -gt 1 -or $observer.total_risk_event_count -gt 1) {
                throw 'VULCAN_GENUINE_EVENT_NOT_UNIQUE'
            }
            if ($process.HasExited) { throw 'VULCAN_GENUINE_EVENT_PAPER_EXITED_BEFORE_DELIVERY' }
            if ($observer.matching_events.Count -eq 1) {
                Start-Sleep -Seconds 2
                Receive-ObserverRequests $observer $expectedUuid $expectedPluginVersion
                break
            }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $triggerDeadline)
        if ($observer.invalid_request_count -ne 0 -or
                $observer.matching_events.Count -ne 1 -or
                $observer.total_risk_event_count -ne 1) {
            throw 'VULCAN_GENUINE_EVENT_DELIVERY_NOT_OBSERVED_EXACTLY_ONCE'
        }
        $matched = $observer.matching_events[0]
    } finally {
        Stop-LoopbackObserver $observer
        try {
            if ($null -ne $process) {
                Stop-OwnedProcess $process $processId $processStartTimeUtc $processMarker
                $process.Dispose()
            }
            $remaining = @(Get-MarkerProcesses $processMarker).Count
            if ($remaining -ne 0) { throw 'VULCAN_GENUINE_EVENT_MARKER_PROCESS_REMAINED' }
        } catch { $cleanupFailure = $_.Exception.Message }
        try {
            if (Test-Path -LiteralPath $serverRoot) {
                $null = Assert-DescendantPath $runRoot $serverRoot
                Remove-Item -LiteralPath $serverRoot -Recurse -Force
            }
            $temporaryRemoved = -not (Test-Path -LiteralPath $serverRoot)
        } catch {
            if ($null -eq $cleanupFailure) {
                $cleanupFailure = 'VULCAN_GENUINE_EVENT_TEMPORARY_MATERIAL_CLEANUP_FAILED'
            }
        }
        try {
            $remapAfterCleanup = Get-RemapState @(
                $lockedVulcan.path, $lockedPaper.path, $lockedMCAce.path)
            if ($remapAfterCleanup.manifest_sha256 -cne $remapBefore.manifest_sha256 -or
                    $remapAfterCleanup.file_count -ne $remapBefore.file_count) {
                throw 'VULCAN_GENUINE_EVENT_ORIGINAL_ARTIFACT_PARENT_REMAP_CHANGED'
            }
        } catch {
            if ($null -eq $cleanupFailure) { $cleanupFailure = $_.Exception.Message }
        }
        if ($null -ne $cleanupFailure) { throw $cleanupFailure }
    }
    if ($null -eq $matched -or $remaining -ne 0 -or -not $temporaryRemoved) {
        throw 'VULCAN_GENUINE_EVENT_FAILED_OR_CLEANUP_INCOMPLETE'
    }
    $preparedAfter = Assert-PreparedAssets $preparedBinding.path $expectedPrepared
    if ($preparedAfter.manifest_sha256 -cne $preparedBinding.manifest_sha256 -or
            $preparedAfter.file_count -ne $preparedBinding.file_count) {
        throw 'VULCAN_GENUINE_EVENT_PREPARED_CACHE_CHANGED_DURING_RUN'
    }
    $report = [ordered]@{
        schema = $reportSchema
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        source_mode = 'EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED'
        vulcan_sha256 = $expectedVulcan
        paper_sha256 = $expectedPaper
        mcace_sha256 = $expectedMCAce
        vulcan_size = [long]$lockedVulcan.length
        paper_size = [long]$lockedPaper.length
        mcace_size = [long]$lockedMCAce.length
        plugin_name = 'Vulcan'
        plugin_version = $expectedPluginVersion
        provider = 'vulcan'
        provider_version = $expectedPluginVersion
        event_type = 'BEHAVIOR_HIGH_RISK'
        source_component = 'vulcan-adapter'
        origin = 'SERVER_CONFIRMED'
        network_policy = 'DENY_ALL_OPERATOR_ATTESTATION'
        network_isolation_operator_attested = $true
        network_isolation_os_verified_by_script = $false
        genuine_external_trigger_operator_attested = $true
        no_synthetic_event_injection_operator_attested = $true
        gate_invoked_plugin_manager_call_event = $false
        gate_used_test_fixture = $false
        gate_used_vendor_synthetic_event = $false
        paper_process_coverage = $true
        licensed_plugin_enablement_coverage = $true
        mcace_listener_registration_coverage = $true
        mcace_adapter_extraction_coverage = $true
        mcace_correlator_coverage = $true
        mcace_queue_auth_delivery_coverage = $true
        real_behavior_event_delivery_coverage = $true
        expected_player_matched = $true
        unique_matching_event_count = 1
        total_risk_event_count = 1
        check_nonempty = $matched.check_nonempty
        stable_check_nonempty = $matched.stable_check_nonempty
        flag_count = [int64]$matched.flag_count
        temporary_paper_remap_allowed = $true
        temporary_material_removed = $true
        remaining_marker_process_count = 0
        limitations = @(
            'HUMAN_TRIGGER_ORIGIN_OPERATOR_ATTESTED_NOT_OS_OR_VENDOR_VERIFIED_BY_SCRIPT',
            'NETWORK_ISOLATION_OPERATOR_ATTESTED_NOT_OS_VERIFIED_BY_SCRIPT')
        passed = $true
    }
    $reportRaw = $report | ConvertTo-Json -Depth 6
    Assert-SanitizedEvidence $reportRaw
    $reportBytes = [Text.UTF8Encoding]::new($false).GetBytes($reportRaw)
    $reportPath = Join-Path $runRoot 'report.json'
    [IO.File]::WriteAllBytes($reportPath, $reportBytes)
    $binding = [ordered]@{
        schema = $bindingSchema
        report_schema = $reportSchema
        report_generated_at = $report.generated_at
        report_sha256 = Get-BytesSha256 $reportBytes
        source_mode = 'EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED'
        vulcan_sha256 = $expectedVulcan
        paper_sha256 = $expectedPaper
        mcace_sha256 = $expectedMCAce
        wrapper_sha256 = $currentBinding.wrapper_sha256
        source_manifest_sha256 = $currentBinding.source_manifest_sha256
        source_file_count = $currentBinding.source_file_count
        java_executable_sha256 = $currentBinding.java_executable_sha256
        java_file_version = $currentBinding.java_file_version
        prepared_manifest_sha256 = $preparedBinding.manifest_sha256
        prepared_file_count = $preparedBinding.file_count
        passed = $true
    }
    $bindingRaw = $binding | ConvertTo-Json -Depth 4
    Assert-SanitizedEvidence $bindingRaw
    [IO.File]::WriteAllText(
        (Join-Path $runRoot 'binding.json'), $bindingRaw, [Text.UTF8Encoding]::new($false))
    $null = Assert-EvidencePair `
        $reportPath $expectedVulcan $expectedPaper $expectedMCAce $expectedPrepared
    Write-Output 'VULCAN_GENUINE_EVENT_PASS|sanitized-report-retained'
} finally {
    Stop-LoopbackObserver $observer
    if ($null -ne $lockedMCAce) { $lockedMCAce.stream.Dispose() }
    if ($null -ne $lockedPaper) { $lockedPaper.stream.Dispose() }
    if ($null -ne $lockedVulcan) { $lockedVulcan.stream.Dispose() }
}
