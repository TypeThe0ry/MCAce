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
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')] [string]$SourceCommit,
    [Parameter(Mandatory)]
    [ValidatePattern('^0\.0\.1$')] [string]$ProductVersion,
    [Parameter(ParameterSetName = 'Execute')] [switch]$ReleaseGradeV3,
    [Parameter(ParameterSetName = 'Execute')] [string]$SupervisorExchangeRoot,
    [Parameter(ParameterSetName = 'Execute')] [string]$SupervisorTrustRootPath,
    [Parameter(ParameterSetName = 'Execute')]
    [ValidatePattern('^[0-9a-fA-F]{64}$')] [string]$ExpectedSupervisorTrustRootSha256,
    [Parameter(ParameterSetName = 'Execute')]
    [ValidateRange(30, 900)] [int]$SupervisorReceiptTimeoutSeconds = 300,
    [ValidateRange(30, 900)] [int]$HumanTriggerTimeoutSeconds = 300,
    [ValidateRange(1, 1440)] [int]$MaximumReportAgeMinutes = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runsRoot = Join-Path $repoRoot 'build\vulcan-genuine-event\runs'
$wrapperPath = Join-Path $PSScriptRoot 'vulcan-genuine-event-smoke.ps1'
$reportSchema = 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_V2'
$bindingSchema = 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_BINDING_V2'
$commitSchema = 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_COMMIT_V2'
$reviewedVulcanSha256 = '7ee3a4fdd7e9da5269f9efc327478e507563e6e7df7abec2222acd3b499bc993'
$expectedPluginVersion = '2.9.0'
$serverId = 'vulcan-genuine-event-gate'
$observerAuthProtocol = 'MCACE_VULCAN_OBSERVER_AUTH_V1'
$observerPublicKeyDerBase64 = 'MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='
$observerChallengeTtlSeconds = 30
$observerTokenTtlSeconds = 90

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

function ConvertTo-SourceCommit([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw 'VULCAN_GENUINE_EVENT_SOURCE_COMMIT_INVALID'
    }
    $normalized = $Value.Trim().ToLowerInvariant()
    if ($normalized -notmatch '^[0-9a-f]{40}$') {
        throw 'VULCAN_GENUINE_EVENT_SOURCE_COMMIT_INVALID'
    }
    return $normalized
}

function Assert-KnownGitSourceCommit([string]$ExpectedCommit) {
    & git -C $repoRoot cat-file -e "$ExpectedCommit`^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw 'VULCAN_GENUINE_EVENT_SOURCE_COMMIT_UNKNOWN'
    }
}

function Assert-ExactGitSourceIdentity([string]$ExpectedCommit) {
    Assert-KnownGitSourceCommit $ExpectedCommit
    $head = [string](& git -C $repoRoot rev-parse --verify HEAD 2>$null)
    if ($LASTEXITCODE -ne 0 -or $head.Trim().ToLowerInvariant() -cne $ExpectedCommit) {
        throw 'VULCAN_GENUINE_EVENT_SOURCE_HEAD_MISMATCH'
    }
    & git -C $repoRoot diff-index --quiet HEAD --
    if ($LASTEXITCODE -ne 0) {
        throw 'VULCAN_GENUINE_EVENT_SOURCE_WORKTREE_DIRTY'
    }
    $untracked = @(& git -C $repoRoot ls-files --others --exclude-standard)
    if ($LASTEXITCODE -ne 0 -or $untracked.Count -ne 0) {
        throw 'VULCAN_GENUINE_EVENT_SOURCE_WORKTREE_DIRTY'
    }
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

function ConvertTo-Base64Url([byte[]]$Bytes) {
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-StrictBase64Url(
        [string]$Value, [int]$ExpectedByteLength, [string]$Field) {
    if ($null -eq $Value -or $ExpectedByteLength -lt 0) {
        throw "VULCAN_GENUINE_EVENT_BASE64URL_INVALID: $Field"
    }
    $expectedCharacters = [int](4 * [Math]::Ceiling($ExpectedByteLength / 3.0)) -
        ((3 - ($ExpectedByteLength % 3)) % 3)
    if ($Value.Length -ne $expectedCharacters -or
            ($Value.Length -gt 0 -and $Value -cnotmatch '^[A-Za-z0-9_-]+$')) {
        throw "VULCAN_GENUINE_EVENT_BASE64URL_INVALID: $Field"
    }
    $standard = $Value.Replace('-', '+').Replace('_', '/')
    $padding = (4 - ($standard.Length % 4)) % 4
    if ($padding -gt 0) { $standard += ('=' * $padding) }
    try { [byte[]]$decoded = [Convert]::FromBase64String($standard) }
    catch { throw "VULCAN_GENUINE_EVENT_BASE64URL_INVALID: $Field" }
    if ($decoded.Length -ne $ExpectedByteLength -or
            (ConvertTo-Base64Url $decoded) -cne $Value) {
        throw "VULCAN_GENUINE_EVENT_BASE64URL_INVALID: $Field"
    }
    return ,$decoded
}

function New-RandomBase64Url([int]$ByteLength) {
    if ($ByteLength -lt 16 -or $ByteLength -gt 64) {
        throw 'VULCAN_GENUINE_EVENT_RANDOM_LENGTH_INVALID'
    }
    $bytes = New-Object byte[] $ByteLength
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) }
    finally { $generator.Dispose() }
    return ConvertTo-Base64Url $bytes
}

function ConvertFrom-StrictUtcInstant([object]$Value, [string]$Field) {
    if ($Value -isnot [string] -or
            $Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$') {
        throw "VULCAN_GENUINE_EVENT_TIMESTAMP_INVALID: $Field"
    }
    $parsed = [DateTimeOffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor
        [Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTimeOffset]::TryParse(
            $Value, [Globalization.CultureInfo]::InvariantCulture,
            $styles, [ref]$parsed) -or $parsed.Offset -ne [TimeSpan]::Zero) {
        throw "VULCAN_GENUINE_EVENT_TIMESTAMP_INVALID: $Field"
    }
    return $parsed
}

function ConvertTo-CanonicalUtcInstant([DateTimeOffset]$Value) {
    return $Value.ToUniversalTime().ToString(
        "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

function Write-Ed25519VerifierSource([string]$Root) {
    $resolvedRoot = Assert-DirectLocalPath $Root -Directory
    $path = Assert-DescendantPath $resolvedRoot (Join-Path $resolvedRoot 'MCAceEd25519Verify.java')
    if (Test-Path -LiteralPath $path) {
        throw 'VULCAN_GENUINE_EVENT_VERIFIER_SOURCE_ALREADY_EXISTS'
    }
    $source = @'
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class MCAceEd25519Verify {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) System.exit(2);
        byte[] publicKey = Base64.getDecoder().decode(args[0]);
        byte[] payload = Base64.getUrlDecoder().decode(args[1]);
        byte[] signature = Base64.getUrlDecoder().decode(args[2]);
        if (signature.length != 64) System.exit(3);
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(KeyFactory.getInstance("Ed25519")
                .generatePublic(new X509EncodedKeySpec(publicKey)));
        verifier.update(payload);
        System.exit(verifier.verify(signature) ? 0 : 4);
    }
}
'@
    [IO.File]::WriteAllText($path, $source, [Text.Encoding]::ASCII)
    return $path
}

function Initialize-Ed25519Verifier([string]$JavaPath, [string]$Root) {
    $resolvedJava = Assert-DirectLocalPath $JavaPath
    $resolvedRoot = Assert-DirectLocalPath $Root -Directory
    $source = Write-Ed25519VerifierSource $resolvedRoot
    $compiler = Assert-DirectLocalPath (
        Join-Path ([IO.Path]::GetDirectoryName($resolvedJava)) 'javac.exe')
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $compiler '-encoding' 'US-ASCII' '-d' $resolvedRoot $source *> $null
        $exitCode = $LASTEXITCODE
    } catch {
        $exitCode = -1
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    $classFile = Join-Path $resolvedRoot 'MCAceEd25519Verify.class'
    if ($exitCode -ne 0 -or -not (Test-Path -LiteralPath $classFile -PathType Leaf)) {
        throw 'VULCAN_GENUINE_EVENT_ED25519_VERIFIER_COMPILE_FAILED'
    }
    $null = Assert-DirectLocalPath $classFile
    return $resolvedRoot
}

function Test-Ed25519Signature(
        [string]$JavaPath, [string]$VerifierRoot,
        [string]$PublicKeyDerBase64, [string]$SigningPayload,
        [string]$EncodedSignature) {
    try {
        $resolvedJava = Assert-DirectLocalPath $JavaPath
        $resolvedVerifierRoot = Assert-DirectLocalPath $VerifierRoot -Directory
        $null = Assert-DirectLocalPath (
            Join-Path $resolvedVerifierRoot 'MCAceEd25519Verify.class')
        $null = ConvertFrom-StrictBase64Url $EncodedSignature 64 'signature'
        if ($SigningPayload.Length -gt 4096 -or
                ($SigningPayload.Length -gt 0 -and
                    $SigningPayload -cnotmatch '^[A-Za-z0-9_-]+$')) {
            return $false
        }
        [byte[]]$publicKey = [Convert]::FromBase64String($PublicKeyDerBase64)
        if ($publicKey.Length -ne 44) { return $false }
    } catch { return $false }
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $resolvedJava '-cp' $resolvedVerifierRoot 'MCAceEd25519Verify' `
            $PublicKeyDerBase64 $SigningPayload $EncodedSignature `
            *> $null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    } finally {
        $ErrorActionPreference = $previousPreference
    }
}

function Write-AtomicEvidenceBytes([string]$Path, [byte[]]$Bytes) {
    $parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
    $null = Assert-DirectLocalPath $parent -Directory
    $target = Assert-DescendantPath $parent $Path
    if (Test-Path -LiteralPath $target) {
        throw 'VULCAN_GENUINE_EVENT_EVIDENCE_ALREADY_EXISTS'
    }
    $temporary = Assert-DescendantPath $parent (
        Join-Path $parent ('.' + [IO.Path]::GetFileName($target) + '.' +
            [guid]::NewGuid().ToString('N') + '.tmp'))
    $stream = $null
    try {
        $stream = [IO.FileStream]::new(
            $temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        [IO.File]::Move($temporary, $target)
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Assert-DirectLocalPath([string]$Path, [switch]$Directory) {
    $windowsPlatform = $env:OS -ceq 'Windows_NT'
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('"') -or
            -not [System.IO.Path]::IsPathRooted($Path) -or
            ($windowsPlatform -and $Path -notmatch '^[A-Za-z]:[\\/]')) {
        throw 'VULCAN_GENUINE_EVENT_ABSOLUTE_LOCAL_PATH_REQUIRED'
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($windowsPlatform) {
        $root = [System.IO.Path]::GetPathRoot($fullPath)
        $drive = [System.IO.DriveInfo]::new($root)
        if ($drive.DriveType -ne [System.IO.DriveType]::Fixed) {
            throw 'VULCAN_GENUINE_EVENT_FIXED_LOCAL_DRIVE_REQUIRED'
        }
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

function New-ObserverSigningPayload(
        [string]$Protocol, [string]$RunNonce, [string]$ServerIdentity,
        [string]$ChallengeId, [DateTimeOffset]$IssuedAt,
        [DateTimeOffset]$ExpiresAt, [string]$ChallengeNonce) {
    $canonical = $Protocol + "`n" +
        'run_nonce=' + $RunNonce + "`n" +
        'server_id=' + $ServerIdentity + "`n" +
        'challenge_id=' + $ChallengeId + "`n" +
        'issued_at_epoch_ms=' + $IssuedAt.ToUnixTimeMilliseconds() + "`n" +
        'expires_at_epoch_ms=' + $ExpiresAt.ToUnixTimeMilliseconds() + "`n" +
        'challenge_nonce=' + $ChallengeNonce
    return ConvertTo-Base64Url ([Text.UTF8Encoding]::new($false).GetBytes($canonical))
}

function Set-ObserverChallenge([object]$Observer, [DateTimeOffset]$Now) {
    if ($Observer.challenge_issued) {
        throw 'VULCAN_GENUINE_EVENT_CHALLENGE_ALREADY_ISSUED'
    }
    $Observer.challenge_id = [guid]::NewGuid().ToString('N')
    $Observer.challenge_issued_at = $Now
    $Observer.challenge_expires_at = $Now.AddSeconds($observerChallengeTtlSeconds)
    $Observer.signing_payload = New-ObserverSigningPayload `
        $Observer.auth_protocol $Observer.run_nonce $Observer.server_id `
        $Observer.challenge_id $Observer.challenge_issued_at `
        $Observer.challenge_expires_at (New-RandomBase64Url 32)
    $Observer.challenge_issued = $true
}

function Test-ObserverChallengeExchangeWindow(
        [object]$Observer, [DateTimeOffset]$Now) {
    return $Observer.challenge_issued -and -not $Observer.challenge_consumed -and
        $Now -ge $Observer.challenge_issued_at -and $Now -lt $Observer.challenge_expires_at
}

function Get-ObserverAccessTokenBinding([object]$Observer) {
    $canonical = $Observer.auth_protocol + "`n" +
        'run_nonce=' + $Observer.run_nonce + "`n" +
        'server_id=' + $Observer.server_id + "`n" +
        'challenge_id=' + $Observer.challenge_id + "`n" +
        'challenge_issued_at_epoch_ms=' + $Observer.challenge_issued_at.ToUnixTimeMilliseconds() + "`n" +
        'challenge_expires_at_epoch_ms=' + $Observer.challenge_expires_at.ToUnixTimeMilliseconds() + "`n" +
        'token_issued_at_epoch_ms=' + $Observer.token_issued_at.ToUnixTimeMilliseconds() + "`n" +
        'token_expires_at_epoch_ms=' + $Observer.token_expires_at.ToUnixTimeMilliseconds() + "`n" +
        'access_token=' + $Observer.access_token
    return Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($canonical))
}

function Test-ObserverRiskAuthorization(
        [object]$Observer, [string]$Authorization, [DateTimeOffset]$Now) {
    if (-not $Observer.token_issued -or -not $Observer.challenge_consumed -or
            -not $Observer.challenge_signature_verified -or
            $Now -lt $Observer.token_issued_at -or $Now -ge $Observer.token_expires_at -or
            $Authorization -cne ('Bearer ' + $Observer.access_token)) {
        return $false
    }
    $currentBinding = Get-ObserverAccessTokenBinding $Observer
    return $currentBinding -ceq $Observer.access_token_binding
}

function New-LoopbackObserver(
        [string]$JavaPath, [string]$VerifierRoot, [string]$RunNonce) {
    if ($RunNonce -cnotmatch '^[0-9a-f]{32}$') {
        throw 'VULCAN_GENUINE_EVENT_RUN_NONCE_INVALID'
    }
    $listener = [System.Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $endpoint = [Net.IPEndPoint]$listener.LocalEndpoint
    $verifierClassRoot = Initialize-Ed25519Verifier $JavaPath $VerifierRoot
    return [pscustomobject]@{
        listener = $listener
        port = [int]$endpoint.Port
        accept_task = $listener.AcceptTcpClientAsync()
        auth_protocol = $observerAuthProtocol
        java_path = $JavaPath
        verifier_root = $verifierClassRoot
        public_key_der_base64 = $observerPublicKeyDerBase64
        run_nonce = $RunNonce
        run_started_at = [DateTimeOffset]::UtcNow
        server_id = "$serverId-$RunNonce"
        challenge_id = ''
        signing_payload = ''
        challenge_issued_at = [DateTimeOffset]::MinValue
        challenge_expires_at = [DateTimeOffset]::MinValue
        challenge_issued = $false
        challenge_consumed = $false
        challenge_signature_verified = $false
        challenge_exchange_count = 0
        access_token = ''
        access_token_binding = ''
        token_issued_at = [DateTimeOffset]::MinValue
        token_expires_at = [DateTimeOffset]::MinValue
        token_issued = $false
        token_binding_verified_count = 0
        invalid_request_count = 0
        total_risk_event_count = 0
        seen_event_ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
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

function Test-JsonArray([object]$Value) {
    return $Value -is [Array]
}

function Get-JsonGraphPropertyCount([object]$Value) {
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return 0 }
    if ($Value -is [Collections.IDictionary]) {
        $count = @($Value.Keys).Count
        foreach ($key in @($Value.Keys)) { $count += Get-JsonGraphPropertyCount $Value[$key] }
        return $count
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $properties = @($Value.PSObject.Properties)
        $count = $properties.Count
        foreach ($property in $properties) { $count += Get-JsonGraphPropertyCount $property.Value }
        return $count
    }
    if ($Value -is [Collections.IEnumerable]) {
        $count = 0
        foreach ($item in $Value) { $count += Get-JsonGraphPropertyCount $item }
        return $count
    }
    return 0
}

function Assert-NoCaseAmbiguousJsonProperties([object]$Value) {
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return }
    if ($Value -is [Collections.IDictionary]) {
        $names = @($Value.Keys | ForEach-Object { [string]$_ })
        if (@($names | Group-Object { $_.ToLowerInvariant() } |
                Where-Object Count -gt 1).Count -gt 0) {
            throw 'VULCAN_GENUINE_EVENT_JSON_CASE_AMBIGUOUS_PROPERTY'
        }
        foreach ($key in @($Value.Keys)) { Assert-NoCaseAmbiguousJsonProperties $Value[$key] }
        return
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $properties = @($Value.PSObject.Properties)
        $names = @($properties | ForEach-Object Name)
        if (@($names | Group-Object { $_.ToLowerInvariant() } |
                Where-Object Count -gt 1).Count -gt 0) {
            throw 'VULCAN_GENUINE_EVENT_JSON_CASE_AMBIGUOUS_PROPERTY'
        }
        foreach ($property in $properties) {
            Assert-NoCaseAmbiguousJsonProperties $property.Value
        }
        return
    }
    if ($Value -is [Collections.IEnumerable]) {
        foreach ($item in $Value) { Assert-NoCaseAmbiguousJsonProperties $item }
    }
}

function ConvertFrom-StrictJsonRaw([string]$Raw) {
    if ([string]::IsNullOrWhiteSpace($Raw)) {
        throw 'VULCAN_GENUINE_EVENT_JSON_EMPTY'
    }
    $trimmed = $Raw.Trim()
    if ($trimmed.Length -lt 2 -or $trimmed[0] -cne '{' -or
            $trimmed[$trimmed.Length - 1] -cne '}') {
        throw 'VULCAN_GENUINE_EVENT_TOP_LEVEL_OBJECT_REQUIRED'
    }
    $command = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
    if ($command.Parameters.ContainsKey('DateKind')) {
        $value = ConvertFrom-Json -InputObject $Raw -DateKind String -ErrorAction Stop
    } else {
        $value = ConvertFrom-Json -InputObject $Raw -ErrorAction Stop
    }
    $propertyTokens = [regex]::Matches(
        $Raw,
        '(?:\{|,)\s*"(?:\\["\\/bfnrt]|\\u[0-9a-fA-F]{4}|[^"\\])*"\s*:',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
    if ($propertyTokens -ne (Get-JsonGraphPropertyCount $value)) {
        throw 'VULCAN_GENUINE_EVENT_DUPLICATE_OR_AMBIGUOUS_PROPERTY'
    }
    Assert-NoCaseAmbiguousJsonProperties $value
    return $value
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
        [object]$Payload, [string]$ExpectedUuid, [string]$ExpectedVersion,
        [DateTimeOffset]$RunStartedAt, [DateTimeOffset]$TokenIssuedAt,
        [DateTimeOffset]$ReceivedAt,
        [Collections.Generic.HashSet[string]]$SeenEventIds) {
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
            -not [guid]::TryParseExact($Payload.player_uuid, 'D', [ref]$playerId) -or
            $Payload.event_id -cne $eventId.ToString('D') -or
            $Payload.player_uuid -cne $playerId.ToString('D')) {
        return $null
    }
    try { $observedAt = ConvertFrom-StrictUtcInstant $Payload.observed_at 'observed_at' }
    catch { return $null }
    $details = $Payload.details
    if ($null -eq $details) { return $null }
    $detailNames = @('schema', 'provider', 'provider_version', 'check', 'stable_check',
        'provider_event_id_sha256','flag_count', 'window_ms', 'first_observed_at', 'maximum_violation_level',
        'experimental', 'independent_providers')
    if (-not (Test-ExactProperties $details $detailNames)) { return $null }
    foreach ($name in @('schema', 'provider', 'provider_version', 'check', 'stable_check',
            'provider_event_id_sha256','first_observed_at')) {
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
    try {
        $firstObserved = ConvertFrom-StrictUtcInstant `
            $details.first_observed_at 'first_observed_at'
    } catch { return $null }
    $providers = @($details.independent_providers)
    if ($Payload.player_uuid.ToLowerInvariant() -cne $ExpectedUuid -or
            $Payload.type -cne 'BEHAVIOR_HIGH_RISK' -or
            $Payload.source_component -cne 'vulcan-adapter' -or
            $Payload.origin -cne 'SERVER_CONFIRMED' -or $Payload.corroborated -or
            $details.schema -cne 'mcace.behavior-alert.v1' -or
            $details.provider -cne 'vulcan' -or $details.provider_version -cne $ExpectedVersion -or
            [string]::IsNullOrWhiteSpace($details.check) -or
            [string]::IsNullOrWhiteSpace($details.stable_check) -or
            $details.provider_event_id_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [int64]$details.flag_count -lt 1 -or [int64]$details.window_ms -lt 1 -or
            [int64]$details.window_ms -gt 600000 -or
            $details.experimental -or $providers.Count -ne 1 -or $providers[0] -cne 'vulcan') {
        return $null
    }
    $observedWindowMs = ($observedAt - $firstObserved).TotalMilliseconds
    if ($RunStartedAt -gt $firstObserved -or $firstObserved -gt $observedAt -or
            $observedAt -gt $TokenIssuedAt -or $TokenIssuedAt -gt $ReceivedAt -or
            $observedWindowMs -lt 0 -or
            $observedWindowMs -gt [int64]$details.window_ms -or
            $SeenEventIds.Contains($Payload.event_id)) {
        return $null
    }
    if (-not $SeenEventIds.Add($Payload.event_id)) { return $null }
    return [pscustomobject]@{
        flag_count = [int64]$details.flag_count
        event_id = [string]$Payload.event_id
        provider_event_id_sha256 = [string]$details.provider_event_id_sha256
        player_uuid = [string]$Payload.player_uuid
        check = [string]$details.check
        stable_check = [string]$details.stable_check
        first_observed_at = [string]$details.first_observed_at
        observed_at = [string]$Payload.observed_at
        maximum_violation_level = [double]$maximumViolation
        check_nonempty = $true
        stable_check_nonempty = $true
        event_causality_verified = $true
        token_run_binding_verified = $true
    }
}

function Invoke-ObserverRequest(
        [object]$Observer, [Net.Sockets.TcpClient]$Client,
        [string]$ExpectedUuid, [string]$ExpectedVersion) {
    try {
        $request = Read-ObserverRequest $Client
        $json = $null
        try { $json = ConvertFrom-StrictJsonRaw $request.body } catch {
            $Observer.invalid_request_count++
            Write-ObserverResponse $request.stream 400 '{"error":"invalid_json"}'
            return
        }
        if ($request.path -ceq '/v1/auth/challenges') {
            if (-not (Test-ExactProperties $json @('server_id')) -or
                    -not (Test-JsonString $json.server_id) -or
                    $json.server_id -cne $Observer.server_id -or
                    $Observer.challenge_issued) {
                $Observer.invalid_request_count++
                Write-ObserverResponse $request.stream 400 '{"error":"invalid_challenge"}'
                return
            }
            Set-ObserverChallenge $Observer ([DateTimeOffset]::UtcNow)
            $body = [ordered]@{
                challenge_id = $Observer.challenge_id
                signing_payload = $Observer.signing_payload
                expires_at = $Observer.challenge_expires_at.ToString('o')
            } | ConvertTo-Json -Compress
            Write-ObserverResponse $request.stream 201 $body
            return
        }
        if ($request.path -ceq '/v1/auth/tokens') {
            if (-not (Test-ExactProperties $json @('challenge_id', 'server_id', 'signature')) -or
                    -not (Test-JsonString $json.challenge_id) -or
                    -not (Test-JsonString $json.server_id) -or
                    -not (Test-JsonString $json.signature) -or
                    $json.challenge_id -cne $Observer.challenge_id -or
                    $json.server_id -cne $Observer.server_id) {
                $Observer.invalid_request_count++
                Write-ObserverResponse $request.stream 400 '{"error":"invalid_token_request"}'
                return
            }
            $now = [DateTimeOffset]::UtcNow
            $available = Test-ObserverChallengeExchangeWindow $Observer $now
            $Observer.challenge_consumed = $true
            $Observer.challenge_exchange_count++
            if (-not $available -or $Observer.challenge_exchange_count -ne 1 -or
                    -not (Test-Ed25519Signature `
                        $Observer.java_path $Observer.verifier_root `
                        $Observer.public_key_der_base64 $Observer.signing_payload `
                        $json.signature)) {
                $Observer.invalid_request_count++
                Write-ObserverResponse $request.stream 401 '{"error":"invalid_client_proof"}'
                return
            }
            $Observer.challenge_signature_verified = $true
            $Observer.access_token = New-RandomBase64Url 32
            $Observer.token_issued_at = $now
            $Observer.token_expires_at = $now.AddSeconds($observerTokenTtlSeconds)
            $Observer.token_issued = $true
            $Observer.access_token_binding = Get-ObserverAccessTokenBinding $Observer
            $body = [ordered]@{
                access_token = $Observer.access_token
                expires_at = $Observer.token_expires_at.ToString('o')
            } | ConvertTo-Json -Compress
            Write-ObserverResponse $request.stream 201 $body
            return
        }
        if ($request.path -ceq '/v1/risk-events') {
            $authorization = if ($request.headers.ContainsKey('Authorization')) {
                $request.headers['Authorization']
            } else { '' }
            $receivedAt = [DateTimeOffset]::UtcNow
            $authorized = Test-ObserverRiskAuthorization `
                $Observer $authorization $receivedAt
            if (-not $authorized) {
                $Observer.invalid_request_count++
                Write-ObserverResponse $request.stream 401 '{"error":"unauthorized"}'
                return
            }
            $Observer.token_binding_verified_count++
            $Observer.total_risk_event_count++
            $matched = Test-GenuineRiskPayload `
                $json $ExpectedUuid $ExpectedVersion $Observer.run_started_at `
                $Observer.token_issued_at $receivedAt $Observer.seen_event_ids
            if ($null -eq $matched) {
                $Observer.invalid_request_count++
                Write-ObserverResponse $request.stream 400 '{"error":"invalid_or_replayed_event"}'
                return
            }
            $matched | Add-Member -NotePropertyName raw_body -NotePropertyValue $request.body
            $matched | Add-Member -NotePropertyName raw_body_sha256 -NotePropertyValue (
                Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($request.body)))
            $matched | Add-Member -NotePropertyName received_at -NotePropertyValue $receivedAt.ToString('o')
            $Observer.matching_events.Add($matched)
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
        [string]$ServerRoot, [int]$PaperPort, [int]$ObserverPort,
        [string]$ObserverServerId, [string]$PreparedRoot) {
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
  server-id: "$ObserverServerId"
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
            size = [long]$bytes.Length
            stream = $stream
        }
    } catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}

function Assert-ReportRaw(
        [string]$Raw, [string]$ExpectedVulcan,
        [string]$ExpectedPaper, [string]$ExpectedMCAce,
        [string]$ExpectedSourceCommit, [string]$ExpectedProductVersion) {
    $names = @(
        'schema', 'generated_at', 'source_mode', 'source_commit', 'product_version',
        'release_eligible',
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
        'observer_auth_protocol', 'observer_challenge_signature_verified',
        'observer_challenge_exchange_count', 'observer_access_token_run_bound',
        'observer_event_causality_verified', 'observer_distinct_event_count',
        'unique_matching_event_count', 'total_risk_event_count',
        'check_nonempty', 'stable_check_nonempty', 'flag_count',
        'temporary_paper_remap_allowed', 'temporary_material_removed',
        'remaining_marker_process_count', 'limitations', 'passed')
    try { $report = ConvertFrom-StrictJsonRaw $Raw }
    catch { throw 'VULCAN_GENUINE_EVENT_REPORT_JSON_INVALID' }
    if (-not (Test-ExactProperties $report $names)) {
        throw 'VULCAN_GENUINE_EVENT_REPORT_PROPERTIES_INVALID'
    }
    foreach ($name in @('schema', 'generated_at', 'source_mode', 'source_commit',
            'product_version', 'vulcan_sha256',
            'paper_sha256', 'mcace_sha256', 'plugin_name', 'plugin_version', 'provider',
            'provider_version', 'event_type', 'source_component', 'origin', 'network_policy',
            'observer_auth_protocol')) {
        if (-not (Test-JsonString $report.$name)) {
            throw 'VULCAN_GENUINE_EVENT_REPORT_TYPE_INVALID'
        }
    }
    foreach ($name in @('release_eligible', 'network_isolation_operator_attested',
            'network_isolation_os_verified_by_script',
            'genuine_external_trigger_operator_attested',
            'no_synthetic_event_injection_operator_attested',
            'gate_invoked_plugin_manager_call_event', 'gate_used_test_fixture',
            'gate_used_vendor_synthetic_event', 'paper_process_coverage',
            'licensed_plugin_enablement_coverage', 'mcace_listener_registration_coverage',
            'mcace_adapter_extraction_coverage', 'mcace_correlator_coverage',
            'mcace_queue_auth_delivery_coverage', 'real_behavior_event_delivery_coverage',
            'expected_player_matched', 'observer_challenge_signature_verified',
            'observer_access_token_run_bound', 'observer_event_causality_verified',
            'check_nonempty', 'stable_check_nonempty',
            'temporary_paper_remap_allowed', 'temporary_material_removed', 'passed')) {
        if (-not (Test-JsonBoolean $report.$name)) {
            throw 'VULCAN_GENUINE_EVENT_REPORT_TYPE_INVALID'
        }
    }
    foreach ($name in @('vulcan_size', 'paper_size', 'mcace_size',
            'observer_challenge_exchange_count', 'observer_distinct_event_count',
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
    if ($limitations.Count -ne 4 -or
            $limitations[0] -cne 'HUMAN_TRIGGER_ORIGIN_OPERATOR_ATTESTED_NOT_OS_OR_VENDOR_VERIFIED_BY_SCRIPT' -or
            $limitations[1] -cne 'NETWORK_ISOLATION_OPERATOR_ATTESTED_NOT_OS_VERIFIED_BY_SCRIPT' -or
            $limitations[2] -cne 'OBSERVER_CLIENT_IDENTITY_USES_PUBLIC_RFC8032_TEST_VECTOR_NOT_EXTERNAL_TRUST_ANCHOR' -or
            $limitations[3] -cne 'OPERATOR_ATTESTED_V2_EVIDENCE_NOT_RELEASE_ELIGIBLE_WITHOUT_EXTERNAL_PINNED_SUPERVISOR_RECEIPT') {
        throw 'VULCAN_GENUINE_EVENT_REPORT_LIMITATIONS_INVALID'
    }
    if ($report.schema -cne $reportSchema -or
            $report.source_mode -cne 'EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED' -or
            $report.source_commit -cne $ExpectedSourceCommit -or
            $report.product_version -cne $ExpectedProductVersion -or
            $report.release_eligible -or
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
            $report.observer_auth_protocol -cne $observerAuthProtocol -or
            -not $report.observer_challenge_signature_verified -or
            $report.observer_challenge_exchange_count -ne 1 -or
            -not $report.observer_access_token_run_bound -or
            -not $report.observer_event_causality_verified -or
            $report.observer_distinct_event_count -ne 1 -or
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
        [string]$Raw, [string]$ExpectedReportSha256, [long]$ExpectedReportSize,
        [object]$Report,
        [string]$ExpectedVulcan, [string]$ExpectedPaper,
        [string]$ExpectedMCAce, [string]$ExpectedPrepared,
        [string]$ExpectedSourceCommit, [string]$ExpectedProductVersion) {
    $names = @('schema', 'report_schema', 'report_generated_at', 'report_sha256',
        'report_size_bytes', 'source_mode', 'source_commit', 'product_version',
        'release_eligible',
        'vulcan_sha256', 'paper_sha256', 'mcace_sha256',
        'vulcan_size', 'paper_size', 'mcace_size',
        'wrapper_sha256', 'source_manifest_sha256', 'source_file_count',
        'java_executable_sha256', 'java_file_version',
        'prepared_manifest_sha256', 'prepared_file_count', 'passed')
    try { $binding = ConvertFrom-StrictJsonRaw $Raw }
    catch { throw 'VULCAN_GENUINE_EVENT_BINDING_JSON_INVALID' }
    if (-not (Test-ExactProperties $binding $names)) {
        throw 'VULCAN_GENUINE_EVENT_BINDING_PROPERTIES_INVALID'
    }
    foreach ($name in @('schema', 'report_schema', 'report_generated_at', 'report_sha256',
            'source_mode', 'source_commit', 'product_version',
            'vulcan_sha256', 'paper_sha256', 'mcace_sha256',
            'wrapper_sha256', 'source_manifest_sha256', 'java_executable_sha256',
            'java_file_version', 'prepared_manifest_sha256')) {
        if (-not (Test-JsonString $binding.$name)) {
            throw 'VULCAN_GENUINE_EVENT_BINDING_TYPE_INVALID'
        }
    }
    foreach ($name in @('report_size_bytes', 'vulcan_size', 'paper_size', 'mcace_size',
            'source_file_count', 'prepared_file_count')) {
        if (-not (Test-JsonInteger $binding.$name)) {
            throw 'VULCAN_GENUINE_EVENT_BINDING_TYPE_INVALID'
        }
    }
    if (-not (Test-JsonBoolean $binding.release_eligible) -or
            -not (Test-JsonBoolean $binding.passed)) {
        throw 'VULCAN_GENUINE_EVENT_BINDING_TYPE_INVALID'
    }
    $current = Get-CurrentBinding
    if ($binding.schema -cne $bindingSchema -or $binding.report_schema -cne $reportSchema -or
            $binding.report_generated_at -cne $Report.generated_at -or
            $binding.report_sha256 -cne $ExpectedReportSha256 -or
            $binding.report_size_bytes -ne $ExpectedReportSize -or
            $binding.source_mode -cne 'EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED' -or
            $binding.source_commit -cne $ExpectedSourceCommit -or
            $binding.product_version -cne $ExpectedProductVersion -or
            $binding.release_eligible -or
            $binding.vulcan_sha256 -cne $ExpectedVulcan -or
            $binding.paper_sha256 -cne $ExpectedPaper -or
            $binding.mcace_sha256 -cne $ExpectedMCAce -or
            $binding.vulcan_size -ne $Report.vulcan_size -or
            $binding.paper_size -ne $Report.paper_size -or
            $binding.mcace_size -ne $Report.mcace_size -or
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
    return $binding
}

function Assert-CommitRaw(
        [string]$Raw, [string]$ExpectedReportSha256, [long]$ExpectedReportSize,
        [string]$ExpectedBindingSha256, [long]$ExpectedBindingSize,
        [object]$Report, [string]$ExpectedSourceCommit,
        [string]$ExpectedProductVersion) {
    $names = @('schema', 'generated_at', 'report_schema', 'binding_schema',
        'report_generated_at', 'report_sha256', 'report_size_bytes',
        'binding_sha256', 'binding_size_bytes', 'source_mode', 'source_commit',
        'product_version', 'release_eligible', 'committed')
    try { $commit = ConvertFrom-StrictJsonRaw $Raw }
    catch { throw 'VULCAN_GENUINE_EVENT_COMMIT_JSON_INVALID' }
    if (-not (Test-ExactProperties $commit $names)) {
        throw 'VULCAN_GENUINE_EVENT_COMMIT_PROPERTIES_INVALID'
    }
    foreach ($name in @('schema', 'generated_at', 'report_schema', 'binding_schema',
            'report_generated_at', 'report_sha256', 'binding_sha256', 'source_mode',
            'source_commit', 'product_version')) {
        if (-not (Test-JsonString $commit.$name)) {
            throw 'VULCAN_GENUINE_EVENT_COMMIT_TYPE_INVALID'
        }
    }
    foreach ($name in @('report_size_bytes', 'binding_size_bytes')) {
        if (-not (Test-JsonInteger $commit.$name)) {
            throw 'VULCAN_GENUINE_EVENT_COMMIT_TYPE_INVALID'
        }
    }
    if (-not (Test-JsonBoolean $commit.release_eligible) -or
            -not (Test-JsonBoolean $commit.committed) -or
            $commit.schema -cne $commitSchema -or
            $commit.generated_at -cne $Report.generated_at -or
            $commit.report_schema -cne $reportSchema -or
            $commit.binding_schema -cne $bindingSchema -or
            $commit.report_generated_at -cne $Report.generated_at -or
            $commit.report_sha256 -cne $ExpectedReportSha256 -or
            $commit.report_size_bytes -ne $ExpectedReportSize -or
            $commit.binding_sha256 -cne $ExpectedBindingSha256 -or
            $commit.binding_size_bytes -ne $ExpectedBindingSize -or
            $commit.source_mode -cne 'EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED' -or
            $commit.source_commit -cne $ExpectedSourceCommit -or
            $commit.product_version -cne $ExpectedProductVersion -or
            $commit.release_eligible -or
            -not $commit.committed) {
        throw 'VULCAN_GENUINE_EVENT_COMMIT_INVALID'
    }
    return $commit
}

function Assert-EvidenceTriplet(
        [string]$ReportPath, [string]$ExpectedVulcan,
        [string]$ExpectedPaper, [string]$ExpectedMCAce, [string]$ExpectedPrepared,
        [string]$ExpectedSourceCommit, [string]$ExpectedProductVersion) {
    $reportEvidence = $null
    $bindingEvidence = $null
    $commitEvidence = $null
    try {
        $directory = Assert-DirectLocalPath (Split-Path $ReportPath -Parent) -Directory
        $expectedNames = @('binding.json', 'commit.json', 'report.json')
        $entries = @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)
        if ($entries.Count -ne $expectedNames.Count -or
                ((@($entries.Name | Sort-Object) -join '|') -cne
                    (($expectedNames | Sort-Object) -join '|'))) {
            throw 'VULCAN_GENUINE_EVENT_EVIDENCE_FILE_SET_INVALID'
        }
        foreach ($entry in $entries) {
            if ($entry.PSIsContainer -or
                    ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    ($entry.PSObject.Properties.Name -contains 'LinkType' -and
                        $null -ne $entry.LinkType)) {
                throw 'VULCAN_GENUINE_EVENT_EVIDENCE_REPARSE_REJECTED'
            }
        }
        $canonicalReport = [IO.Path]::GetFullPath((Join-Path $directory 'report.json'))
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath($ReportPath), $canonicalReport,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'VULCAN_GENUINE_EVENT_CANONICAL_REPORT_PATH_REQUIRED'
        }
        $reportEvidence = Open-LockedEvidence $canonicalReport
        $bindingEvidence = Open-LockedEvidence (Join-Path $directory 'binding.json')
        $commitEvidence = Open-LockedEvidence (Join-Path $directory 'commit.json')
        $report = Assert-ReportRaw `
            $reportEvidence.raw $ExpectedVulcan $ExpectedPaper $ExpectedMCAce `
            $ExpectedSourceCommit $ExpectedProductVersion
        $null = Assert-BindingRaw `
            $bindingEvidence.raw $reportEvidence.sha256 $reportEvidence.size $report `
            $ExpectedVulcan $ExpectedPaper $ExpectedMCAce $ExpectedPrepared `
            $ExpectedSourceCommit $ExpectedProductVersion
        $null = Assert-CommitRaw `
            $commitEvidence.raw $reportEvidence.sha256 $reportEvidence.size `
            $bindingEvidence.sha256 $bindingEvidence.size $report `
            $ExpectedSourceCommit $ExpectedProductVersion
        return $report
    } finally {
        if ($null -ne $commitEvidence) { $commitEvidence.stream.Dispose() }
        if ($null -ne $bindingEvidence) { $bindingEvidence.stream.Dispose() }
        if ($null -ne $reportEvidence) { $reportEvidence.stream.Dispose() }
    }
}

function Get-LatestReport {
    if (-not (Test-Path -LiteralPath $runsRoot -PathType Container)) { return $null }
    return Get-ChildItem -LiteralPath $runsRoot -Directory -Force |
        Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 } |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'commit.json') -PathType Leaf } |
        ForEach-Object {
            Get-Item -LiteralPath (Join-Path $_.FullName 'report.json') -ErrorAction SilentlyContinue
        } | Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}

# Release-grade V3 uses a separate, externally operated supervisor.  The runner writes a
# canonical signing request into an exchange directory outside the repository and accepts only a
# pinned RSA receipt.  Producer documents remain release_eligible=false; publication is the sole
# promotion point after independent revalidation.
$v3ReportSchema = 'MCACE_VULCAN_GENUINE_EVENT_REPORT_V3'
$v3BindingSchema = 'MCACE_VULCAN_GENUINE_EVENT_BINDING_V3'
$v3CommitSchema = 'MCACE_VULCAN_GENUINE_EVENT_COMMIT_V3'
$v3SigningRequestSchema = 'MCACE_VULCAN_GENUINE_EVENT_SIGNING_REQUEST_V1'
$v3ReceiptSchema = 'MCACE_VULCAN_GENUINE_EVENT_SUPERVISOR_RECEIPT_V1'
$v3TrustRootSchema = 'MCACE_VULCAN_GENUINE_EVENT_SUPERVISOR_TRUST_ROOT_V1'
$v3SigningDomain = 'MCACE-VULCAN-GENUINE-EVENT-SUPERVISOR-RECEIPT-V1'
$v3ReceiptPropertyNames = @(
    'schema','artifact_class','source_mode','signed_at','expires_at','source_commit',
    'product_version','run_attempt_id','challenge_nonce','challenge_issued_at',
    'signing_request_sha256','report_sha256','report_size_bytes','binding_sha256',
    'binding_size_bytes','raw_event_sha256','raw_event_size_bytes','callback_ledger_sha256',
    'callback_ledger_size_bytes','callback_record_sha256','vulcan_sha256','vulcan_size',
    'paper_sha256','paper_size','mcace_sha256','mcace_size','paper_process_id',
    'paper_process_started_at','paper_process_incarnation_sha256','provider_plugin_name',
    'provider_plugin_version','provider_plugin_main_class','provider_event_class',
    'accessor_provenance_sha256','signer_key_id','signer_trust_root_sha256',
    'signature_algorithm','fixture','signature_base64')

function Test-RsaPkcs1Sha256Signature(
        [byte[]]$Payload, [byte[]]$Signature, [byte[]]$Modulus, [byte[]]$Exponent) {
    $rsa = [Security.Cryptography.RSACryptoServiceProvider]::new()
    try {
        $rsa.PersistKeyInCsp = $false
        $rsa.ImportParameters([Security.Cryptography.RSAParameters]@{
            Modulus=$Modulus; Exponent=$Exponent
        })
        return $rsa.VerifyData($Payload, 'SHA256', $Signature)
    } finally { $rsa.Dispose() }
}

function Get-VulcanV3ReceiptSigningPayload([object]$Receipt) {
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add($v3SigningDomain)
    foreach ($name in @($v3ReceiptPropertyNames | Where-Object { $_ -cne 'signature_base64' })) {
        $value = $Receipt.$name
        if ($value -is [bool]) { $rendered = if ([bool]$value) { 'true' } else { 'false' } }
        elseif (Test-JsonInteger $value) {
            $rendered = [Convert]::ToString($value, [Globalization.CultureInfo]::InvariantCulture)
        } else { $rendered = [string]$value }
        if ($rendered -match '[\r\n]' -or $name -match '[\r\n=]') {
            throw 'VULCAN_GENUINE_EVENT_V3_RECEIPT_SIGNING_VALUE_INVALID'
        }
        $lines.Add("$name=$rendered")
    }
    return [Text.UTF8Encoding]::new($false).GetBytes(($lines -join "`n") + "`n")
}

function Assert-VulcanV3TrustRoot(
        [object]$Evidence, [string]$ExpectedSha256, [string]$ApprovedSha256 = '',
        [switch]$AllowTestFixture) {
    $pin = ConvertTo-Sha256 $ExpectedSha256 'V3SupervisorTrustRootSha256'
    if ([string]$Evidence.sha256 -cne $pin) {
        throw 'VULCAN_GENUINE_EVENT_V3_TRUST_ROOT_PIN_MISMATCH'
    }
    if ([string]::IsNullOrWhiteSpace($ApprovedSha256)) {
        if (-not $AllowTestFixture) {
            throw 'VULCAN_GENUINE_EVENT_V3_APPROVED_TRUST_ROOT_PIN_REQUIRED'
        }
    } elseif ((ConvertTo-Sha256 $ApprovedSha256 'V3ApprovedSupervisorTrustRootSha256') -cne $pin) {
        throw 'VULCAN_GENUINE_EVENT_V3_TRUST_ROOT_NOT_APPROVED'
    }
    $root = ConvertFrom-StrictJsonRaw $Evidence.raw
    if (-not (Test-ExactProperties $root @(
            'schema','artifact_class','key_id','algorithm','modulus_base64',
            'exponent_base64','fixture')) -or
            $root.schema -cne $v3TrustRootSchema -or
            $root.algorithm -cne 'RSA_PKCS1_SHA256' -or
            $root.key_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$' -or
            -not (Test-JsonBoolean $root.fixture)) {
        throw 'VULCAN_GENUINE_EVENT_V3_TRUST_ROOT_SCHEMA_INVALID'
    }
    if ([bool]$root.fixture) {
        if (-not $AllowTestFixture -or
                $root.artifact_class -cne 'TEST_VULCAN_SUPERVISOR_TRUST_ROOT_FIXTURE') {
            throw 'VULCAN_GENUINE_EVENT_V3_FIXTURE_TRUST_ROOT_RELEASE_REJECTED'
        }
    } elseif ($root.artifact_class -cne 'OUT_OF_BAND_PINNED_VULCAN_SUPERVISOR_TRUST_ROOT') {
        throw 'VULCAN_GENUINE_EVENT_V3_TRUST_ROOT_PROVENANCE_INVALID'
    }
    try {
        [byte[]]$modulus = [Convert]::FromBase64String([string]$root.modulus_base64)
        [byte[]]$exponent = [Convert]::FromBase64String([string]$root.exponent_base64)
    } catch { throw 'VULCAN_GENUINE_EVENT_V3_TRUST_ROOT_KEY_ENCODING_INVALID' }
    if ($modulus.Length -lt 256 -or $modulus.Length -gt 512 -or
            $exponent.Length -lt 1 -or $exponent.Length -gt 4) {
        throw 'VULCAN_GENUINE_EVENT_V3_TRUST_ROOT_KEY_SIZE_INVALID'
    }
    return [pscustomobject]@{ value=$root; modulus=$modulus; exponent=$exponent; sha256=$pin }
}

function Get-VulcanV3PathBinding([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) {
        throw 'VULCAN_GENUINE_EVENT_V3_EXCHANGE_ABSOLUTE_PATH_REQUIRED'
    }
    $full = [IO.Path]::GetFullPath($Path)
    $canonical = if ($env:OS -ceq 'Windows_NT') {
        $full.Replace('/', '\').ToLowerInvariant()
    } else { $full }
    return Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($canonical))
}

function Assert-VulcanV3CallbackLedger(
        [object]$Evidence, [object]$RawEvent, [string]$ExpectedAttempt,
        [string]$ExpectedChallenge, [string]$ExpectedVulcan, [string]$ExpectedMCAce,
        [int]$ExpectedProcessId, [string]$ExpectedProcessStartedAt) {
    $raw = [string]$Evidence.raw
    $lines = @($raw -split "`r?`n" | Where-Object { $_ -cne '' })
    if ($lines.Count -ne 1 -or $raw -cne ($lines[0] + "`n")) {
        throw 'VULCAN_GENUINE_EVENT_V3_CALLBACK_LEDGER_CARDINALITY_INVALID'
    }
    $record = ConvertFrom-StrictJsonRaw $lines[0]
    $names = @(
        'schema','sequence','callback_at','capture_attempt_id','capture_challenge_nonce',
        'process_id','process_started_at','process_incarnation_sha256','owner_plugin_name',
        'owner_plugin_version','owner_plugin_main_class','owner_plugin_code_source_sha256',
        'provider_plugin_name','provider_plugin_version','provider_plugin_main_class',
        'provider_plugin_code_source_sha256','registered_event_class',
        'registered_event_code_source_sha256','runtime_event_class',
        'runtime_event_code_source_sha256','handler_owner_plugin','handler_listener_class',
        'handler_priority','handler_ignore_cancelled','callback_thread_id','callback_thread_name',
        'player_uuid','provider_event_id_sha256','check_sha256','stable_check_sha256',
        'violation_hex','observed_at','semantic_fields_sha256','accessor_provenance',
        'accessor_provenance_sha256','previous_record_sha256','record_sha256')
    if (-not (Test-ExactProperties $record $names)) {
        throw 'VULCAN_GENUINE_EVENT_V3_CALLBACK_LEDGER_SCHEMA_INVALID'
    }
    $unsignedPattern = ',"record_sha256":"[0-9a-f]{64}"\}$'
    if ($lines[0] -cnotmatch $unsignedPattern) {
        throw 'VULCAN_GENUINE_EVENT_V3_CALLBACK_RECORD_CANONICAL_INVALID'
    }
    $unsigned = [regex]::Replace($lines[0], $unsignedPattern, '}')
    if ((Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($unsigned))) -cne
            [string]$record.record_sha256) {
        throw 'VULCAN_GENUINE_EVENT_V3_CALLBACK_RECORD_HASH_INVALID'
    }
    $rawDetails = $RawEvent.details
    $checkHash = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes([string]$rawDetails.check))
    $stableHash = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes([string]$rawDetails.stable_check))
    if ([string]$record.violation_hex -cnotmatch '^-?0x[0-9a-f]+(?:\.[0-9a-f]+)?p[+-]?[0-9]+$') {
        throw 'VULCAN_GENUINE_EVENT_V3_CALLBACK_VIOLATION_INVALID'
    }
    $semantic = "player_uuid=$($record.player_uuid)`n" +
        "provider_event_id=$($record.provider_event_id_sha256)`n" +
        "check_sha256=$checkHash`n" + "stable_check_sha256=$stableHash`n" +
        "violation_hex=$($record.violation_hex)`n" + "observed_at=$($record.observed_at)`n"
    $accessorHash = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes(
        [string]$record.accessor_provenance))
    $semanticHash = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($semantic))
    $expectedEventIdHash = [string]$RawEvent.details.provider_event_id_sha256
    $expectedIncarnationHash = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes(
        "pid=$ExpectedProcessId`nstarted_at=$ExpectedProcessStartedAt`n"))
    $callbackAt = ConvertFrom-StrictUtcInstant $record.callback_at 'v3_callback_at'
    $processStartedAt = ConvertFrom-StrictUtcInstant $record.process_started_at `
        'v3_callback_process_started_at'
    $observedAt = ConvertFrom-StrictUtcInstant $record.observed_at 'v3_callback_observed_at'
    if ($record.schema -cne 'MCACE_VULCAN_CALLBACK_PROVENANCE_V1' -or
            -not (Test-JsonInteger $record.sequence) -or [long]$record.sequence -ne 1 -or
            $record.capture_attempt_id -cne $ExpectedAttempt -or
            $record.capture_challenge_nonce -cne $ExpectedChallenge -or
            -not (Test-JsonInteger $record.process_id) -or
            [int]$record.process_id -ne $ExpectedProcessId -or
            $record.process_started_at -cne $ExpectedProcessStartedAt -or
            $record.process_incarnation_sha256 -cne $expectedIncarnationHash -or
            $processStartedAt -gt $callbackAt -or
            [Math]::Abs(($callbackAt-$observedAt).TotalSeconds) -gt 5 -or
            $record.owner_plugin_name -cne 'MCAce' -or
            [string]::IsNullOrWhiteSpace([string]$record.owner_plugin_version) -or
            [string]::IsNullOrWhiteSpace([string]$record.owner_plugin_main_class) -or
            $record.owner_plugin_code_source_sha256 -cne $ExpectedMCAce -or
            $record.provider_plugin_name -cne 'Vulcan' -or
            $record.provider_plugin_version -cne $expectedPluginVersion -or
            [string]::IsNullOrWhiteSpace([string]$record.provider_plugin_main_class) -or
            $record.provider_plugin_code_source_sha256 -cne $ExpectedVulcan -or
            $record.registered_event_class -notin @(
                'me.frep.vulcan.api.event.VulcanFlagEvent',
                'me.frep.vulcan.api.event.VulcanViolationEvent') -or
            $record.runtime_event_class -cne $record.registered_event_class -or
            $record.registered_event_code_source_sha256 -cne $ExpectedVulcan -or
            $record.runtime_event_code_source_sha256 -cne $ExpectedVulcan -or
            $record.handler_owner_plugin -cne 'MCAce' -or
            [string]::IsNullOrWhiteSpace([string]$record.handler_listener_class) -or
            $record.handler_priority -cne 'MONITOR' -or
            -not (Test-JsonBoolean $record.handler_ignore_cancelled) -or
            -not [bool]$record.handler_ignore_cancelled -or
            -not (Test-JsonInteger $record.callback_thread_id) -or
            [long]$record.callback_thread_id -le 0 -or
            [string]::IsNullOrWhiteSpace([string]$record.callback_thread_name) -or
            $record.player_uuid -cne [string]$RawEvent.player_uuid -or
            $record.provider_event_id_sha256 -cne $expectedEventIdHash -or
            $record.check_sha256 -cne $checkHash -or
            $record.stable_check_sha256 -cne $stableHash -or
            # The callback ledger is emitted for the exact alert that created the
            # raw event.  first_observed_at is the correlation-window floor and
            # may legitimately precede this alert when more than one flag was
            # aggregated, so bind the callback to the raw event's top-level
            # observation timestamp instead.
            $record.observed_at -cne [string]$RawEvent.observed_at -or
            $record.semantic_fields_sha256 -cne $semanticHash -or
            $record.accessor_provenance_sha256 -cne $accessorHash -or
            [string]::IsNullOrWhiteSpace([string]$record.accessor_provenance) -or
            $record.accessor_provenance -notmatch '#getPlayer\(\)->' -or
            $record.accessor_provenance -notmatch '#getCheck\(\)->' -or
            $record.previous_record_sha256 -cne ('0' * 64)) {
        throw 'VULCAN_GENUINE_EVENT_V3_CALLBACK_PROVENANCE_INVALID'
    }
    return $record
}

function Assert-VulcanV3Receipt(
        [object]$Evidence, [object]$TrustRoot, [hashtable]$Expected,
        [DateTimeOffset]$Now, [switch]$AllowTestFixture,
        [switch]$RequireCurrentlyValid) {
    $receipt = ConvertFrom-StrictJsonRaw $Evidence.raw
    if (-not (Test-ExactProperties $receipt $v3ReceiptPropertyNames)) {
        throw 'VULCAN_GENUINE_EVENT_V3_RECEIPT_SCHEMA_INVALID'
    }
    foreach ($name in $v3ReceiptPropertyNames) {
        if (-not $Expected.ContainsKey($name) -or
                [string]$receipt.$name -cne [string]$Expected[$name]) {
            throw "VULCAN_GENUINE_EVENT_V3_RECEIPT_BINDING_INVALID: $name"
        }
    }
    if (-not (Test-JsonBoolean $receipt.fixture)) {
        throw 'VULCAN_GENUINE_EVENT_V3_RECEIPT_FIXTURE_TYPE_INVALID'
    }
    if ([bool]$receipt.fixture) {
        if (-not $AllowTestFixture -or
                $receipt.artifact_class -cne 'TEST_VULCAN_SUPERVISOR_RECEIPT_FIXTURE' -or
                $receipt.source_mode -cne 'TEST_SIGNED_CONTRACT_FIXTURE') {
            throw 'VULCAN_GENUINE_EVENT_V3_FIXTURE_RECEIPT_RELEASE_REJECTED'
        }
    } elseif ($receipt.artifact_class -cne 'EXTERNAL_VULCAN_GENUINE_EVENT_RECEIPT' -or
            $receipt.source_mode -cne 'EXTERNAL_RUNTIME_SUPERVISOR') {
        throw 'VULCAN_GENUINE_EVENT_V3_RECEIPT_PROVENANCE_INVALID'
    }
    $signedAt = ConvertFrom-StrictUtcInstant $receipt.signed_at 'v3_receipt_signed_at'
    $expiresAt = ConvertFrom-StrictUtcInstant $receipt.expires_at 'v3_receipt_expires_at'
    $issuedAt = ConvertFrom-StrictUtcInstant $receipt.challenge_issued_at 'v3_challenge_issued_at'
    if ($signedAt -lt $issuedAt -or $expiresAt -le $signedAt -or
            ($signedAt - $issuedAt).TotalMinutes -gt 5 -or
            ($expiresAt - $signedAt).TotalMinutes -gt 15 -or
            ($RequireCurrentlyValid -and $Now.ToUniversalTime() -ge $expiresAt)) {
        throw 'VULCAN_GENUINE_EVENT_V3_RECEIPT_EXPIRED_OR_TIME_INVALID'
    }
    try { [byte[]]$signature = [Convert]::FromBase64String([string]$receipt.signature_base64) }
    catch { throw 'VULCAN_GENUINE_EVENT_V3_RECEIPT_SIGNATURE_ENCODING_INVALID' }
    if ($signature.Length -ne $TrustRoot.modulus.Length -or
            -not (Test-RsaPkcs1Sha256Signature `
                (Get-VulcanV3ReceiptSigningPayload $receipt) $signature `
                $TrustRoot.modulus $TrustRoot.exponent)) {
        throw 'VULCAN_GENUINE_EVENT_V3_RECEIPT_SIGNATURE_INVALID'
    }
    return [pscustomobject]@{ value=$receipt; signed_at=$signedAt; expires_at=$expiresAt }
}

function Open-LockedVulcanV3Evidence([string]$Path, [switch]$Sensitive) {
    $resolved = Assert-DirectLocalPath $Path
    $stream = $null
    try {
        $stream = [IO.File]::Open(
            $resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($stream.Length -le 0 -or $stream.Length -gt 1048576) {
            throw 'VULCAN_GENUINE_EVENT_V3_EVIDENCE_SIZE_INVALID'
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw 'VULCAN_GENUINE_EVENT_V3_EVIDENCE_TRUNCATED' }
            $offset += $read
        }
        $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        if (-not $Sensitive) { Assert-SanitizedEvidence $raw }
        return [pscustomobject]@{
            path=$resolved; raw=$raw; bytes=$bytes; sha256=Get-BytesSha256 $bytes
            size=[long]$bytes.Length; stream=$stream
        }
    } catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}

function Assert-VulcanV3RawRiskEvent([object]$Event) {
    if (-not (Test-ExactProperties $Event @(
            'event_id','player_uuid','type','source_component','origin','corroborated',
            'observed_at','details')) -or
            $Event.type -cne 'BEHAVIOR_HIGH_RISK' -or
            $Event.source_component -cne 'vulcan-adapter' -or
            $Event.origin -cne 'SERVER_CONFIRMED' -or
            -not (Test-JsonBoolean $Event.corroborated) -or [bool]$Event.corroborated) {
        throw 'VULCAN_GENUINE_EVENT_V3_RAW_EVENT_SEMANTICS_INVALID'
    }
    $eventId = [guid]::Empty; $playerId = [guid]::Empty
    if (-not [guid]::TryParseExact([string]$Event.event_id,'D',[ref]$eventId) -or
            -not [guid]::TryParseExact([string]$Event.player_uuid,'D',[ref]$playerId) -or
            $eventId -eq [guid]::Empty -or $playerId -eq [guid]::Empty) {
        throw 'VULCAN_GENUINE_EVENT_V3_RAW_EVENT_IDENTITY_INVALID'
    }
    $details = $Event.details
        if (-not (Test-ExactProperties $details @(
            'schema','provider','provider_version','check','stable_check','provider_event_id_sha256','flag_count',
            'window_ms','first_observed_at','maximum_violation_level','experimental',
            'independent_providers')) -or
            $details.schema -cne 'mcace.behavior-alert.v1' -or
            $details.provider -cne 'vulcan' -or
            $details.provider_version -cne $expectedPluginVersion -or
            [string]::IsNullOrWhiteSpace([string]$details.check) -or
            [string]::IsNullOrWhiteSpace([string]$details.stable_check) -or
            [string]$details.provider_event_id_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-JsonInteger $details.flag_count) -or [long]$details.flag_count -lt 1 -or
            -not (Test-JsonInteger $details.window_ms) -or [long]$details.window_ms -lt 1 -or
            -not (Test-JsonBoolean $details.experimental) -or [bool]$details.experimental -or
            @($details.independent_providers).Count -ne 1 -or
            [string]$details.independent_providers[0] -cne 'vulcan') {
        throw 'VULCAN_GENUINE_EVENT_V3_RAW_EVENT_DETAILS_INVALID'
    }
    $first = ConvertFrom-StrictUtcInstant $details.first_observed_at 'v3_raw_first_observed_at'
    $observed = ConvertFrom-StrictUtcInstant $Event.observed_at 'v3_raw_observed_at'
    if ($first -gt $observed -or ($observed - $first).TotalMilliseconds -gt [long]$details.window_ms) {
        throw 'VULCAN_GENUINE_EVENT_V3_RAW_EVENT_TIME_INVALID'
    }
    return $Event
}

function Assert-VulcanV3Package(
        [string]$Directory, [object]$TrustRootEvidence, [string]$ExpectedTrustRootSha256,
        [string]$ApprovedTrustRootSha256, [string]$ExpectedSourceCommit,
        [string]$ExpectedVulcan, [string]$ExpectedPaper, [string]$ExpectedMCAce,
        [switch]$AllowTestFixture, [switch]$RequireCurrentlyValidReceipt) {
    $root = Assert-DirectLocalPath $Directory -Directory
    $names = @('binding.json','callback-provenance.jsonl','commit.json','raw-risk-event.json',
        'report.json','signing-request.json','supervisor-receipt.json')
    $entries = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
    if ($entries.Count -ne $names.Count -or
            ((@($entries.Name | Sort-Object) -join '|') -cne (($names | Sort-Object) -join '|'))) {
        throw 'VULCAN_GENUINE_EVENT_V3_PACKAGE_FILE_SET_INVALID'
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or
                ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($entry.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $entry.LinkType)) {
            throw 'VULCAN_GENUINE_EVENT_V3_PACKAGE_REPARSE_REJECTED'
        }
    }
    $opened = [Collections.Generic.List[object]]::new()
    try {
        foreach ($name in $names) {
            $sensitive = $name -in @('callback-provenance.jsonl','raw-risk-event.json')
            $opened.Add((Open-LockedVulcanV3Evidence (Join-Path $root $name) -Sensitive:$sensitive))
        }
        function E([string]$Name) { return $opened[$names.IndexOf($Name)] }
        $reportEvidence = E 'report.json'; $bindingEvidence = E 'binding.json'
        $commitEvidence = E 'commit.json'; $rawEvidence = E 'raw-risk-event.json'
        $ledgerEvidence = E 'callback-provenance.jsonl'; $requestEvidence = E 'signing-request.json'
        $receiptEvidence = E 'supervisor-receipt.json'
        $report = ConvertFrom-StrictJsonRaw $reportEvidence.raw
        $binding = ConvertFrom-StrictJsonRaw $bindingEvidence.raw
        $commit = ConvertFrom-StrictJsonRaw $commitEvidence.raw
        $request = ConvertFrom-StrictJsonRaw $requestEvidence.raw
        $rawEvent = Assert-VulcanV3RawRiskEvent (ConvertFrom-StrictJsonRaw $rawEvidence.raw)
        $reportNames = @(
            'schema','generated_at','source_mode','source_commit','product_version',
            'release_eligible','fixture','vulcan_sha256','vulcan_size','paper_sha256','paper_size',
            'mcace_sha256','mcace_size','plugin_name','plugin_version','run_attempt_id',
            'challenge_nonce','challenge_issued_at','capture_started_at','capture_completed_at',
            'paper_process_id','paper_process_started_at','paper_process_incarnation_sha256',
            'provider_plugin_main_class','provider_event_class','provider_event_id_sha256',
            'player_session_identity_sha256','check_sha256','stable_check_sha256',
            'accessor_provenance_sha256','callback_record_sha256','raw_event_sha256',
            'raw_event_size_bytes','callback_ledger_sha256','callback_ledger_size_bytes',
            'plugin_manager_identity_verified','non_synthetic_callback_chain_verified',
            'raw_event_delivery_verified','cleanup_verified','remaining_marker_process_count',
            'limitations','passed')
        $bindingNames = @(
            'schema','report_schema','report_generated_at','report_sha256','report_size_bytes',
            'source_mode','source_commit','product_version','release_eligible','fixture',
            'vulcan_sha256','vulcan_size','paper_sha256','paper_size','mcace_sha256','mcace_size',
            'wrapper_sha256','source_manifest_sha256','source_file_count','java_executable_sha256',
            'java_file_version','prepared_manifest_sha256','prepared_file_count','raw_event_sha256',
            'raw_event_size_bytes','callback_ledger_sha256','callback_ledger_size_bytes',
            'supervisor_trust_root_sha256','passed')
        $requestNames = @(
            'schema','domain','artifact_class','source_mode','source_commit','product_version',
            'run_attempt_id','challenge_nonce','challenge_issued_at','expires_at',
            'report_sha256','report_size_bytes','binding_sha256','binding_size_bytes',
            'raw_event_sha256','raw_event_size_bytes','callback_ledger_sha256',
            'callback_ledger_size_bytes','callback_record_sha256','vulcan_sha256','vulcan_size',
            'paper_sha256','paper_size','mcace_sha256','mcace_size','paper_process_id',
            'paper_process_started_at','paper_process_incarnation_sha256','provider_plugin_name',
            'provider_plugin_version','provider_plugin_main_class','provider_event_class',
            'accessor_provenance_sha256','exchange_path_sha256','receipt_output_path_sha256',
            'signer_key_id','signer_trust_root_sha256','signature_algorithm','fixture')
        $commitNames = @(
            'schema','generated_at','report_schema','binding_schema','signing_request_schema',
            'supervisor_receipt_schema','report_sha256','report_size_bytes','binding_sha256',
            'binding_size_bytes','signing_request_sha256','signing_request_size_bytes',
            'supervisor_receipt_sha256','supervisor_receipt_size_bytes','raw_event_sha256',
            'raw_event_size_bytes','callback_ledger_sha256','callback_ledger_size_bytes',
            'source_mode','source_commit','product_version','release_eligible','fixture','committed')
        if (-not (Test-ExactProperties $report $reportNames) -or
                -not (Test-ExactProperties $binding $bindingNames) -or
                -not (Test-ExactProperties $request $requestNames) -or
                -not (Test-ExactProperties $commit $commitNames)) {
            throw 'VULCAN_GENUINE_EVENT_V3_DOCUMENT_PROPERTY_SET_INVALID'
        }
        if ($report.schema -cne $v3ReportSchema -or $binding.schema -cne $v3BindingSchema -or
                $commit.schema -cne $v3CommitSchema -or
                $request.schema -cne $v3SigningRequestSchema -or
                $request.domain -cne $v3SigningDomain) {
            throw 'VULCAN_GENUINE_EVENT_V3_DOCUMENT_SCHEMA_INVALID'
        }
        $isFixture = [bool]$report.fixture
        foreach ($doc in @($report,$binding,$commit)) {
            if (-not (Test-JsonBoolean $doc.fixture) -or [bool]$doc.fixture -ne $isFixture -or
                    -not (Test-JsonBoolean $doc.release_eligible) -or [bool]$doc.release_eligible -or
                    [string]$doc.source_commit -cne $ExpectedSourceCommit -or
                    [string]$doc.product_version -cne '0.0.1') {
                throw 'VULCAN_GENUINE_EVENT_V3_PRODUCER_IDENTITY_INVALID'
            }
        }
        if (-not (Test-JsonBoolean $request.fixture) -or [bool]$request.fixture -ne $isFixture -or
                [string]$request.source_commit -cne $ExpectedSourceCommit -or
                [string]$request.product_version -cne '0.0.1' -or
                $request.artifact_class -cne $(if ($isFixture) {
                    'TEST_VULCAN_SIGNING_REQUEST_FIXTURE'
                } else { 'VULCAN_GENUINE_EVENT_EXTERNAL_SIGNING_REQUEST' }) -or
                $request.signer_trust_root_sha256 -cne $ExpectedTrustRootSha256.ToLowerInvariant() -or
                $request.signature_algorithm -cne 'RSA_PKCS1_SHA256') {
            throw 'VULCAN_GENUINE_EVENT_V3_SIGNING_REQUEST_IDENTITY_INVALID'
        }
        if ($isFixture -and -not $AllowTestFixture) {
            throw 'VULCAN_GENUINE_EVENT_V3_FIXTURE_PACKAGE_RELEASE_REJECTED'
        }
        if ((!$isFixture -and ($report.source_mode -cne 'EXECUTED_EXTERNAL_SUPERVISED_RUNTIME' -or
                    $request.source_mode -cne 'EXTERNAL_SUPERVISOR_SIGNING_REQUEST')) -or
                ($isFixture -and ($report.source_mode -cne 'TEST_SIGNED_CONTRACT_FIXTURE' -or
                    $request.source_mode -cne 'TEST_SIGNED_CONTRACT_FIXTURE'))) {
            throw 'VULCAN_GENUINE_EVENT_V3_SOURCE_PROVENANCE_INVALID'
        }
        foreach ($name in @('vulcan_sha256','paper_sha256','mcace_sha256')) {
            $expected = switch ($name) {
                vulcan_sha256 { $ExpectedVulcan }; paper_sha256 { $ExpectedPaper }
                default { $ExpectedMCAce }
            }
            if ([string]$report.$name -cne $expected -or [string]$binding.$name -cne $expected -or
                    [string]$request.$name -cne $expected) {
                throw "VULCAN_GENUINE_EVENT_V3_ARTIFACT_HASH_MISMATCH: $name"
            }
        }
        foreach ($name in @('vulcan_size','paper_size','mcace_size')) {
            if (-not (Test-JsonInteger $report.$name) -or [long]$report.$name -le 0 -or
                    [long]$binding.$name -ne [long]$report.$name -or
                    [long]$request.$name -ne [long]$report.$name) {
                throw "VULCAN_GENUINE_EVENT_V3_ARTIFACT_SIZE_INVALID: $name"
            }
        }
        if ($report.vulcan_sha256 -cne $reviewedVulcanSha256 -or
                $report.plugin_name -cne 'Vulcan' -or
                $report.plugin_version -cne $expectedPluginVersion -or
                -not (Test-JsonBoolean $report.plugin_manager_identity_verified) -or
                -not [bool]$report.plugin_manager_identity_verified -or
                -not (Test-JsonBoolean $report.non_synthetic_callback_chain_verified) -or
                -not [bool]$report.non_synthetic_callback_chain_verified -or
                -not (Test-JsonBoolean $report.raw_event_delivery_verified) -or
                -not [bool]$report.raw_event_delivery_verified -or
                -not (Test-JsonBoolean $report.cleanup_verified) -or
                -not [bool]$report.cleanup_verified -or
                [int]$report.remaining_marker_process_count -ne 0 -or
                -not (Test-JsonBoolean $report.passed) -or -not [bool]$report.passed -or
                -not (Test-JsonBoolean $binding.passed) -or -not [bool]$binding.passed -or
                -not (Test-JsonBoolean $commit.committed) -or -not [bool]$commit.committed -or
                -not (Test-JsonArray $report.limitations) -or @($report.limitations).Count -ne 0) {
            throw 'VULCAN_GENUINE_EVENT_V3_GATE_STATE_INVALID'
        }
        if ($binding.report_sha256 -cne $reportEvidence.sha256 -or
                [long]$binding.report_size_bytes -ne $reportEvidence.size -or
                $binding.report_generated_at -cne $report.generated_at -or
                $binding.report_schema -cne $report.schema -or
                $binding.source_mode -cne $report.source_mode -or
                $binding.source_commit -cne $report.source_commit -or
                $binding.product_version -cne $report.product_version -or
                $binding.release_eligible -ne $report.release_eligible -or
                $binding.fixture -ne $report.fixture -or
                $request.report_sha256 -cne $reportEvidence.sha256 -or
                [long]$request.report_size_bytes -ne $reportEvidence.size -or
                $request.binding_sha256 -cne $bindingEvidence.sha256 -or
                [long]$request.binding_size_bytes -ne $bindingEvidence.size -or
                $request.run_attempt_id -cne $report.run_attempt_id -or
                $request.challenge_nonce -cne $report.challenge_nonce -or
                $request.challenge_issued_at -cne $report.challenge_issued_at -or
                $commit.report_sha256 -cne $reportEvidence.sha256 -or
                [long]$commit.report_size_bytes -ne $reportEvidence.size -or
                $commit.binding_sha256 -cne $bindingEvidence.sha256 -or
                [long]$commit.binding_size_bytes -ne $bindingEvidence.size -or
                $commit.signing_request_sha256 -cne $requestEvidence.sha256 -or
                [long]$commit.signing_request_size_bytes -ne $requestEvidence.size -or
                $commit.supervisor_receipt_sha256 -cne $receiptEvidence.sha256 -or
                [long]$commit.supervisor_receipt_size_bytes -ne $receiptEvidence.size -or
                $commit.report_schema -cne $report.schema -or
                $commit.binding_schema -cne $binding.schema -or
                $commit.signing_request_schema -cne $request.schema -or
                $commit.supervisor_receipt_schema -cne $v3ReceiptSchema -or
                $commit.source_mode -cne $report.source_mode -or
                $commit.source_commit -cne $report.source_commit -or
                $commit.product_version -cne $report.product_version -or
                $commit.release_eligible -ne $report.release_eligible -or
                $commit.fixture -ne $report.fixture -or
                $report.raw_event_sha256 -cne $rawEvidence.sha256 -or
                [long]$report.raw_event_size_bytes -ne $rawEvidence.size -or
                $report.callback_ledger_sha256 -cne $ledgerEvidence.sha256 -or
                [long]$report.callback_ledger_size_bytes -ne $ledgerEvidence.size -or
                $binding.raw_event_sha256 -cne $rawEvidence.sha256 -or
                [long]$binding.raw_event_size_bytes -ne $rawEvidence.size -or
                $binding.callback_ledger_sha256 -cne $ledgerEvidence.sha256 -or
                [long]$binding.callback_ledger_size_bytes -ne $ledgerEvidence.size -or
                $request.raw_event_sha256 -cne $rawEvidence.sha256 -or
                [long]$request.raw_event_size_bytes -ne $rawEvidence.size -or
                $request.callback_ledger_sha256 -cne $ledgerEvidence.sha256 -or
                [long]$request.callback_ledger_size_bytes -ne $ledgerEvidence.size -or
                $commit.raw_event_sha256 -cne $rawEvidence.sha256 -or
                [long]$commit.raw_event_size_bytes -ne $rawEvidence.size -or
                $commit.callback_ledger_sha256 -cne $ledgerEvidence.sha256 -or
                [long]$commit.callback_ledger_size_bytes -ne $ledgerEvidence.size) {
            throw 'VULCAN_GENUINE_EVENT_V3_DOCUMENT_CHAIN_INVALID'
        }
        $ledger = Assert-VulcanV3CallbackLedger $ledgerEvidence $rawEvent `
            ([string]$report.run_attempt_id) ([string]$report.challenge_nonce) `
            $ExpectedVulcan $ExpectedMCAce ([int]$report.paper_process_id) `
            ([string]$report.paper_process_started_at)
        $rawCheckHash = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes(
            [string]$rawEvent.details.check))
        $rawStableHash = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes(
            [string]$rawEvent.details.stable_check))
        $expectedPlayerSessionIdentity = Get-BytesSha256 (
            [Text.UTF8Encoding]::new($false).GetBytes(
                "player=$($rawEvent.player_uuid)`nattempt=$($report.run_attempt_id)`n"))
        if ($report.callback_record_sha256 -cne $ledger.record_sha256 -or
                $report.provider_event_id_sha256 -cne $ledger.provider_event_id_sha256 -or
                $report.provider_event_id_sha256 -cne
                    [string]$rawEvent.details.provider_event_id_sha256 -or
                $report.player_session_identity_sha256 -cne $expectedPlayerSessionIdentity -or
                $report.check_sha256 -cne $rawCheckHash -or
                $report.stable_check_sha256 -cne $rawStableHash -or
                $report.accessor_provenance_sha256 -cne $ledger.accessor_provenance_sha256 -or
                $report.provider_event_class -cne $ledger.runtime_event_class -or
                $report.provider_plugin_main_class -cne $ledger.provider_plugin_main_class -or
                $report.paper_process_id -ne $ledger.process_id -or
                $report.paper_process_started_at -cne $ledger.process_started_at -or
                $report.paper_process_incarnation_sha256 -cne $ledger.process_incarnation_sha256 -or
                $request.callback_record_sha256 -cne $ledger.record_sha256 -or
                $request.vulcan_sha256 -cne $report.vulcan_sha256 -or
                [long]$request.vulcan_size -ne [long]$report.vulcan_size -or
                $request.paper_sha256 -cne $report.paper_sha256 -or
                [long]$request.paper_size -ne [long]$report.paper_size -or
                $request.mcace_sha256 -cne $report.mcace_sha256 -or
                [long]$request.mcace_size -ne [long]$report.mcace_size -or
                $request.paper_process_id -ne $ledger.process_id -or
                $request.paper_process_started_at -cne $ledger.process_started_at -or
                $request.paper_process_incarnation_sha256 -cne $ledger.process_incarnation_sha256 -or
                $request.provider_plugin_name -cne 'Vulcan' -or
                $request.provider_plugin_version -cne $expectedPluginVersion -or
                $request.provider_plugin_main_class -cne $ledger.provider_plugin_main_class -or
                $request.provider_event_class -cne $ledger.runtime_event_class -or
                $request.accessor_provenance_sha256 -cne $ledger.accessor_provenance_sha256 -or
                $binding.supervisor_trust_root_sha256 -cne
                    $ExpectedTrustRootSha256.ToLowerInvariant()) {
            throw 'VULCAN_GENUINE_EVENT_V3_RUNTIME_CHAIN_INVALID'
        }
        $trust = Assert-VulcanV3TrustRoot $TrustRootEvidence $ExpectedTrustRootSha256 `
            $ApprovedTrustRootSha256 -AllowTestFixture:$AllowTestFixture
        $receiptExpected = @{}
        $receiptPreview = ConvertFrom-StrictJsonRaw $receiptEvidence.raw
        foreach ($name in $v3ReceiptPropertyNames) { $receiptExpected[$name] = $receiptPreview.$name }
        $expectedReceiptFields = @{
            schema=$v3ReceiptSchema; source_commit=$ExpectedSourceCommit; product_version='0.0.1'
            run_attempt_id=$report.run_attempt_id; challenge_nonce=$report.challenge_nonce
            challenge_issued_at=$report.challenge_issued_at; expires_at=$request.expires_at
            signing_request_sha256=$requestEvidence.sha256
            report_sha256=$reportEvidence.sha256; report_size_bytes=$reportEvidence.size
            binding_sha256=$bindingEvidence.sha256; binding_size_bytes=$bindingEvidence.size
            raw_event_sha256=$rawEvidence.sha256; raw_event_size_bytes=$rawEvidence.size
            callback_ledger_sha256=$ledgerEvidence.sha256; callback_ledger_size_bytes=$ledgerEvidence.size
            callback_record_sha256=$ledger.record_sha256; vulcan_sha256=$ExpectedVulcan
            vulcan_size=$report.vulcan_size; paper_sha256=$ExpectedPaper; paper_size=$report.paper_size
            mcace_sha256=$ExpectedMCAce; mcace_size=$report.mcace_size
            paper_process_id=$report.paper_process_id; paper_process_started_at=$report.paper_process_started_at
            paper_process_incarnation_sha256=$report.paper_process_incarnation_sha256
            provider_plugin_name='Vulcan'; provider_plugin_version=$expectedPluginVersion
            provider_plugin_main_class=$report.provider_plugin_main_class
            provider_event_class=$report.provider_event_class
            accessor_provenance_sha256=$report.accessor_provenance_sha256
            signer_key_id=$trust.value.key_id; signer_trust_root_sha256=$ExpectedTrustRootSha256.ToLowerInvariant()
            signature_algorithm='RSA_PKCS1_SHA256'; fixture=$isFixture
        }
        foreach ($entry in $expectedReceiptFields.GetEnumerator()) {
            $receiptExpected[[string]$entry.Key] = $entry.Value
        }
        $validatedReceipt = Assert-VulcanV3Receipt $receiptEvidence $trust $receiptExpected `
            ([DateTimeOffset]::UtcNow) -AllowTestFixture:$AllowTestFixture `
            -RequireCurrentlyValid:$RequireCurrentlyValidReceipt
        $challengeAt = ConvertFrom-StrictUtcInstant $request.challenge_issued_at `
            'v3_package_challenge_issued_at'
        $requestExpiresAt = ConvertFrom-StrictUtcInstant $request.expires_at `
            'v3_package_request_expires_at'
        $captureStartedAt = ConvertFrom-StrictUtcInstant $report.capture_started_at `
            'v3_package_capture_started_at'
        $captureCompletedAt = ConvertFrom-StrictUtcInstant $report.capture_completed_at `
            'v3_package_capture_completed_at'
        $reportGeneratedAt = ConvertFrom-StrictUtcInstant $report.generated_at `
            'v3_package_report_generated_at'
        $commitGeneratedAt = ConvertFrom-StrictUtcInstant $commit.generated_at `
            'v3_package_commit_generated_at'
        if ($captureStartedAt -lt $challengeAt -or $captureCompletedAt -lt $captureStartedAt -or
                $requestExpiresAt -le $challengeAt -or
                ($requestExpiresAt - $challengeAt).TotalMinutes -gt 15 -or
                $reportGeneratedAt -lt $captureCompletedAt -or
                $reportGeneratedAt -gt $requestExpiresAt -or
                $validatedReceipt.signed_at -lt $reportGeneratedAt -or
                $validatedReceipt.expires_at.UtcDateTime.Ticks -ne
                    $requestExpiresAt.UtcDateTime.Ticks -or
                $commitGeneratedAt -lt $validatedReceipt.signed_at -or
                $commitGeneratedAt -ge $requestExpiresAt) {
            throw 'VULCAN_GENUINE_EVENT_V3_PACKAGE_ACCEPTANCE_WINDOW_INVALID'
        }
        return [pscustomobject]@{
            report=$report; binding=$binding; commit=$commit; request=$request
            receipt=$validatedReceipt.value; ledger=$ledger; raw_event=$rawEvent
            report_evidence=$reportEvidence; binding_evidence=$bindingEvidence
            commit_evidence=$commitEvidence; request_evidence=$requestEvidence
            receipt_evidence=$receiptEvidence; ledger_evidence=$ledgerEvidence
            raw_event_evidence=$rawEvidence; trust_root=$trust
        }
    } finally {
        foreach ($evidence in $opened) { if ($null -ne $evidence.stream) { $evidence.stream.Dispose() } }
    }
}

$expectedVulcan = ConvertTo-Sha256 $VulcanSha256 'VulcanSha256'
$expectedPaper = ConvertTo-Sha256 $PaperSha256 'PaperSha256'
$expectedMCAce = ConvertTo-Sha256 $MCAceSha256 'MCAceSha256'
$expectedPrepared = ConvertTo-Sha256 $PreparedManifestSha256 'PreparedManifestSha256'
$expectedSourceCommit = ConvertTo-SourceCommit $SourceCommit
if ($ProductVersion -cne '0.0.1') {
    throw 'VULCAN_GENUINE_EVENT_PRODUCT_VERSION_INVALID'
}
Assert-KnownGitSourceCommit $expectedSourceCommit
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
    $null = Assert-EvidenceTriplet `
        $path $expectedVulcan $expectedPaper $expectedMCAce $expectedPrepared `
        $expectedSourceCommit $ProductVersion
    Write-Output 'VULCAN_GENUINE_EVENT_PASS|report-only'
    exit 0
}

$v3TrustRootEvidence = $null
$v3TrustRoot = $null
$v3ExchangeRoot = $null
$v3ApprovedPin = ''
if ($ReleaseGradeV3) {
    if ([string]::IsNullOrWhiteSpace($SupervisorExchangeRoot) -or
            [string]::IsNullOrWhiteSpace($SupervisorTrustRootPath) -or
            [string]::IsNullOrWhiteSpace($ExpectedSupervisorTrustRootSha256)) {
        throw 'VULCAN_GENUINE_EVENT_V3_EXTERNAL_EXCHANGE_AND_TRUST_ROOT_REQUIRED'
    }
    $v3ExchangeRoot = Assert-DirectLocalPath $SupervisorExchangeRoot -Directory
    $trustRootFull = Assert-DirectLocalPath $SupervisorTrustRootPath
    $repoPrefix = [IO.Path]::GetFullPath($repoRoot).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    if ($v3ExchangeRoot.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            $trustRootFull.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'VULCAN_GENUINE_EVENT_V3_EXTERNAL_MATERIAL_MUST_BE_OUT_OF_BAND'
    }
    if (@(Get-ChildItem -LiteralPath $v3ExchangeRoot -Force).Count -ne 0) {
        throw 'VULCAN_GENUINE_EVENT_V3_EXCHANGE_NOT_EMPTY'
    }
    $v3ApprovedPin = [Environment]::GetEnvironmentVariable(
        'MCACE_VULCAN_SUPERVISOR_TRUST_ROOT_SHA256','Process')
    if ([string]::IsNullOrWhiteSpace($v3ApprovedPin)) {
        throw 'VULCAN_GENUINE_EVENT_V3_APPROVED_TRUST_ROOT_PIN_REQUIRED'
    }
    $v3TrustRootEvidence = Open-LockedVulcanV3Evidence $trustRootFull
    $v3TrustRoot = Assert-VulcanV3TrustRoot $v3TrustRootEvidence `
        $ExpectedSupervisorTrustRootSha256 $v3ApprovedPin
} elseif (-not [string]::IsNullOrWhiteSpace($SupervisorExchangeRoot) -or
        -not [string]::IsNullOrWhiteSpace($SupervisorTrustRootPath) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedSupervisorTrustRootSha256)) {
    throw 'VULCAN_GENUINE_EVENT_V3_PARAMETERS_REQUIRE_RELEASE_GRADE_V3'
}

if (-not $Execute -or -not $AllowTemporaryPaperRemap -or
        $NetworkPolicy -cne 'DenyAll' -or -not $NetworkIsolationAttested -or
        -not $GenuineExternalTriggerAttested -or -not $NoSyntheticEventInjectionAttested) {
    throw 'VULCAN_GENUINE_EVENT_EXPLICIT_EXECUTION_AND_ATTESTATIONS_REQUIRED'
}
Assert-ExactGitSourceIdentity $expectedSourceCommit
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
    $v3ChallengeNonce = if ($ReleaseGradeV3) {
        ([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N'))
    } else { '' }
    $v3ChallengeIssuedAt = if ($ReleaseGradeV3) { [DateTimeOffset]::UtcNow } `
        else { [DateTimeOffset]::MinValue }
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
        $observer = New-LoopbackObserver $java $serverRoot $runToken
        Write-ServerConfiguration `
            $serverRoot $PaperListenPort $observer.port $observer.server_id $preparedBinding.path
        $isolatedPrepared = Assert-PreparedAssets $serverRoot $expectedPrepared
        if ($isolatedPrepared.file_count -ne $preparedBinding.file_count) {
            throw 'VULCAN_GENUINE_EVENT_ISOLATED_PREPARED_COPY_COUNT_MISMATCH'
        }
        $stdout = Join-Path $serverRoot 'paper.stdout.log'
        $stderr = Join-Path $serverRoot 'paper.stderr.log'
        $arguments = @(
            '-Dpaper.disableStartupVersionCheck=true',
            "-Dmcace.vulcan.genuine.event.run=$processMarker")
        if ($ReleaseGradeV3) {
            $arguments += @(
                "-Dmcace.vulcan.provenance.ledger=$(Join-Path $runRoot 'callback-provenance.jsonl')",
                "-Dmcace.vulcan.provenance.attempt=$runToken",
                "-Dmcace.vulcan.provenance.challenge=$v3ChallengeNonce")
        }
        $arguments += @(
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
                $observer.total_risk_event_count -ne 1 -or
                -not $observer.challenge_issued -or
                -not $observer.challenge_consumed -or
                -not $observer.challenge_signature_verified -or
                $observer.challenge_exchange_count -ne 1 -or
                -not $observer.token_issued -or
                $observer.token_binding_verified_count -ne 1 -or
                $observer.seen_event_ids.Count -ne 1) {
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
    if ($ReleaseGradeV3) {
        $rawEventBytes = [Text.UTF8Encoding]::new($false).GetBytes([string]$matched.raw_body)
        if ((Get-BytesSha256 $rawEventBytes) -cne [string]$matched.raw_body_sha256) {
            throw 'VULCAN_GENUINE_EVENT_V3_RAW_EVENT_CAPTURE_CHANGED'
        }
        $rawEventPath = Join-Path $runRoot 'raw-risk-event.json'
        Write-AtomicEvidenceBytes $rawEventPath $rawEventBytes
        $rawEventEvidence = Open-LockedVulcanV3Evidence $rawEventPath -Sensitive
        $ledgerEvidence = Open-LockedVulcanV3Evidence `
            (Join-Path $runRoot 'callback-provenance.jsonl') -Sensitive
        try {
            $rawEvent = Assert-VulcanV3RawRiskEvent (
                ConvertFrom-StrictJsonRaw $rawEventEvidence.raw)
            $ledgerPreview = ConvertFrom-StrictJsonRaw (
                (($ledgerEvidence.raw -split "`r?`n")[0]))
            $ledger = Assert-VulcanV3CallbackLedger $ledgerEvidence $rawEvent `
                $runToken $v3ChallengeNonce $expectedVulcan $expectedMCAce `
                $processId ([string]$ledgerPreview.process_started_at)
            $ledgerStarted = ConvertFrom-StrictUtcInstant `
                $ledger.process_started_at 'v3_ledger_process_started_at'
            if ([Math]::Abs(($ledgerStarted.UtcDateTime - $processStartTimeUtc).TotalSeconds) -gt 2) {
                throw 'VULCAN_GENUINE_EVENT_V3_PROCESS_START_IDENTITY_MISMATCH'
            }
            $expectedIncarnation = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes(
                "pid=$processId`nstarted_at=$($ledger.process_started_at)`n"))
            if ($ledger.process_incarnation_sha256 -cne $expectedIncarnation) {
                throw 'VULCAN_GENUINE_EVENT_V3_PROCESS_INCARNATION_HASH_INVALID'
            }
            $captureCompletedAt = [DateTimeOffset]::UtcNow
            $report = [ordered]@{
                schema=$v3ReportSchema; generated_at=ConvertTo-CanonicalUtcInstant $captureCompletedAt
                source_mode='EXECUTED_EXTERNAL_SUPERVISED_RUNTIME'; source_commit=$expectedSourceCommit
                product_version=$ProductVersion; release_eligible=$false; fixture=$false
                vulcan_sha256=$expectedVulcan; vulcan_size=[long]$lockedVulcan.length
                paper_sha256=$expectedPaper; paper_size=[long]$lockedPaper.length
                mcace_sha256=$expectedMCAce; mcace_size=[long]$lockedMCAce.length
                plugin_name='Vulcan'; plugin_version=$expectedPluginVersion
                run_attempt_id=$runToken; challenge_nonce=$v3ChallengeNonce
                challenge_issued_at=ConvertTo-CanonicalUtcInstant $v3ChallengeIssuedAt
                capture_started_at=ConvertTo-CanonicalUtcInstant $observer.run_started_at
                capture_completed_at=ConvertTo-CanonicalUtcInstant $captureCompletedAt
                paper_process_id=[int]$processId
                paper_process_started_at=[string]$ledger.process_started_at
                paper_process_incarnation_sha256=[string]$ledger.process_incarnation_sha256
                provider_plugin_main_class=[string]$ledger.provider_plugin_main_class
                provider_event_class=[string]$ledger.runtime_event_class
                provider_event_id_sha256=[string]$ledger.provider_event_id_sha256
                player_session_identity_sha256=Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes(
                    "player=$($rawEvent.player_uuid)`nattempt=$runToken`n"))
                check_sha256=[string]$ledger.check_sha256
                stable_check_sha256=[string]$ledger.stable_check_sha256
                accessor_provenance_sha256=[string]$ledger.accessor_provenance_sha256
                callback_record_sha256=[string]$ledger.record_sha256
                raw_event_sha256=[string]$rawEventEvidence.sha256
                raw_event_size_bytes=[long]$rawEventEvidence.size
                callback_ledger_sha256=[string]$ledgerEvidence.sha256
                callback_ledger_size_bytes=[long]$ledgerEvidence.size
                plugin_manager_identity_verified=$true
                non_synthetic_callback_chain_verified=$true
                raw_event_delivery_verified=$true; cleanup_verified=$true
                remaining_marker_process_count=0; limitations=@(); passed=$true
            }
            $reportRaw = $report | ConvertTo-Json -Depth 6
            Assert-SanitizedEvidence $reportRaw
            $reportBytes = [Text.UTF8Encoding]::new($false).GetBytes($reportRaw)
            $reportPath = Join-Path $runRoot 'report.json'
            Write-AtomicEvidenceBytes $reportPath $reportBytes
            $binding = [ordered]@{
                schema=$v3BindingSchema; report_schema=$v3ReportSchema
                report_generated_at=$report.generated_at; report_sha256=Get-BytesSha256 $reportBytes
                report_size_bytes=[long]$reportBytes.Length
                source_mode=$report.source_mode; source_commit=$expectedSourceCommit
                product_version=$ProductVersion; release_eligible=$false; fixture=$false
                vulcan_sha256=$expectedVulcan; vulcan_size=[long]$lockedVulcan.length
                paper_sha256=$expectedPaper; paper_size=[long]$lockedPaper.length
                mcace_sha256=$expectedMCAce; mcace_size=[long]$lockedMCAce.length
                wrapper_sha256=$currentBinding.wrapper_sha256
                source_manifest_sha256=$currentBinding.source_manifest_sha256
                source_file_count=$currentBinding.source_file_count
                java_executable_sha256=$currentBinding.java_executable_sha256
                java_file_version=$currentBinding.java_file_version
                prepared_manifest_sha256=$preparedBinding.manifest_sha256
                prepared_file_count=$preparedBinding.file_count
                raw_event_sha256=[string]$rawEventEvidence.sha256
                raw_event_size_bytes=[long]$rawEventEvidence.size
                callback_ledger_sha256=[string]$ledgerEvidence.sha256
                callback_ledger_size_bytes=[long]$ledgerEvidence.size
                supervisor_trust_root_sha256=$ExpectedSupervisorTrustRootSha256.ToLowerInvariant()
                passed=$true
            }
            $bindingRaw = $binding | ConvertTo-Json -Depth 5
            Assert-SanitizedEvidence $bindingRaw
            $bindingBytes = [Text.UTF8Encoding]::new($false).GetBytes($bindingRaw)
            $bindingPath = Join-Path $runRoot 'binding.json'
            Write-AtomicEvidenceBytes $bindingPath $bindingBytes
            $exchangeRequestPath = Join-Path $v3ExchangeRoot "request-$runToken.json"
            $exchangeReceiptPath = Join-Path $v3ExchangeRoot "receipt-$runToken.json"
            $request = [ordered]@{
                schema=$v3SigningRequestSchema; domain=$v3SigningDomain
                artifact_class='VULCAN_GENUINE_EVENT_EXTERNAL_SIGNING_REQUEST'
                source_mode='EXTERNAL_SUPERVISOR_SIGNING_REQUEST'
                source_commit=$expectedSourceCommit; product_version=$ProductVersion
                run_attempt_id=$runToken; challenge_nonce=$v3ChallengeNonce
                challenge_issued_at=ConvertTo-CanonicalUtcInstant $v3ChallengeIssuedAt
                expires_at=ConvertTo-CanonicalUtcInstant ($v3ChallengeIssuedAt.AddMinutes(15))
                report_sha256=Get-BytesSha256 $reportBytes; report_size_bytes=[long]$reportBytes.Length
                binding_sha256=Get-BytesSha256 $bindingBytes; binding_size_bytes=[long]$bindingBytes.Length
                raw_event_sha256=[string]$rawEventEvidence.sha256
                raw_event_size_bytes=[long]$rawEventEvidence.size
                callback_ledger_sha256=[string]$ledgerEvidence.sha256
                callback_ledger_size_bytes=[long]$ledgerEvidence.size
                callback_record_sha256=[string]$ledger.record_sha256
                vulcan_sha256=$expectedVulcan; vulcan_size=[long]$lockedVulcan.length
                paper_sha256=$expectedPaper; paper_size=[long]$lockedPaper.length
                mcace_sha256=$expectedMCAce; mcace_size=[long]$lockedMCAce.length
                paper_process_id=[int]$processId
                paper_process_started_at=[string]$ledger.process_started_at
                paper_process_incarnation_sha256=[string]$ledger.process_incarnation_sha256
                provider_plugin_name='Vulcan'; provider_plugin_version=$expectedPluginVersion
                provider_plugin_main_class=[string]$ledger.provider_plugin_main_class
                provider_event_class=[string]$ledger.runtime_event_class
                accessor_provenance_sha256=[string]$ledger.accessor_provenance_sha256
                exchange_path_sha256=Get-VulcanV3PathBinding $v3ExchangeRoot
                receipt_output_path_sha256=Get-VulcanV3PathBinding $exchangeReceiptPath
                signer_key_id=[string]$v3TrustRoot.value.key_id
                signer_trust_root_sha256=$ExpectedSupervisorTrustRootSha256.ToLowerInvariant()
                signature_algorithm='RSA_PKCS1_SHA256'; fixture=$false
            }
            $requestRaw = $request | ConvertTo-Json -Depth 5
            Assert-SanitizedEvidence $requestRaw
            $requestBytes = [Text.UTF8Encoding]::new($false).GetBytes($requestRaw)
            Write-AtomicEvidenceBytes (Join-Path $runRoot 'signing-request.json') $requestBytes
            Write-AtomicEvidenceBytes $exchangeRequestPath $requestBytes
            Write-Output "VULCAN_GENUINE_EVENT_V3_SIGNING_REQUEST_READY|$exchangeRequestPath"
            $receiptDeadline = [DateTime]::UtcNow.AddSeconds($SupervisorReceiptTimeoutSeconds)
            while (-not (Test-Path -LiteralPath $exchangeReceiptPath -PathType Leaf) -and
                    [DateTime]::UtcNow -lt $receiptDeadline) {
                Start-Sleep -Milliseconds 250
            }
            if (-not (Test-Path -LiteralPath $exchangeReceiptPath -PathType Leaf)) {
                throw 'VULCAN_GENUINE_EVENT_V3_SUPERVISOR_RECEIPT_TIMEOUT'
            }
            $exchangeNames = @((Get-ChildItem -LiteralPath $v3ExchangeRoot -Force).Name | Sort-Object)
            if (($exchangeNames -join '|') -cne ((@(
                    "receipt-$runToken.json","request-$runToken.json") | Sort-Object) -join '|')) {
                throw 'VULCAN_GENUINE_EVENT_V3_EXCHANGE_FILE_SET_INVALID'
            }
            $receiptInput = Open-LockedVulcanV3Evidence $exchangeReceiptPath
            try {
                Write-AtomicEvidenceBytes (Join-Path $runRoot 'supervisor-receipt.json') `
                    $receiptInput.bytes
                $receiptPreview = ConvertFrom-StrictJsonRaw $receiptInput.raw
                $receiptExpected = @{}
                foreach ($name in $v3ReceiptPropertyNames) { $receiptExpected[$name]=$receiptPreview.$name }
                foreach ($entry in @{
                        schema=$v3ReceiptSchema; source_commit=$expectedSourceCommit
                        product_version=$ProductVersion; run_attempt_id=$runToken
                        challenge_nonce=$v3ChallengeNonce
                        challenge_issued_at=ConvertTo-CanonicalUtcInstant $v3ChallengeIssuedAt
                        expires_at=$request.expires_at
                        signing_request_sha256=Get-BytesSha256 $requestBytes
                        report_sha256=Get-BytesSha256 $reportBytes; report_size_bytes=[long]$reportBytes.Length
                        binding_sha256=Get-BytesSha256 $bindingBytes; binding_size_bytes=[long]$bindingBytes.Length
                        raw_event_sha256=$rawEventEvidence.sha256; raw_event_size_bytes=$rawEventEvidence.size
                        callback_ledger_sha256=$ledgerEvidence.sha256
                        callback_ledger_size_bytes=$ledgerEvidence.size
                        callback_record_sha256=$ledger.record_sha256
                        vulcan_sha256=$expectedVulcan; vulcan_size=[long]$lockedVulcan.length
                        paper_sha256=$expectedPaper; paper_size=[long]$lockedPaper.length
                        mcace_sha256=$expectedMCAce; mcace_size=[long]$lockedMCAce.length
                        paper_process_id=[int]$processId
                        paper_process_started_at=$ledger.process_started_at
                        paper_process_incarnation_sha256=$ledger.process_incarnation_sha256
                        provider_plugin_name='Vulcan'; provider_plugin_version=$expectedPluginVersion
                        provider_plugin_main_class=$ledger.provider_plugin_main_class
                        provider_event_class=$ledger.runtime_event_class
                        accessor_provenance_sha256=$ledger.accessor_provenance_sha256
                        signer_key_id=$v3TrustRoot.value.key_id
                        signer_trust_root_sha256=$ExpectedSupervisorTrustRootSha256.ToLowerInvariant()
                        signature_algorithm='RSA_PKCS1_SHA256'; fixture=$false
                    }.GetEnumerator()) { $receiptExpected[[string]$entry.Key]=$entry.Value }
                $null = Assert-VulcanV3Receipt $receiptInput $v3TrustRoot $receiptExpected `
                    ([DateTimeOffset]::UtcNow) -RequireCurrentlyValid
                $commit = [ordered]@{
                    schema=$v3CommitSchema; generated_at=ConvertTo-CanonicalUtcInstant ([DateTimeOffset]::UtcNow)
                    report_schema=$v3ReportSchema; binding_schema=$v3BindingSchema
                    signing_request_schema=$v3SigningRequestSchema
                    supervisor_receipt_schema=$v3ReceiptSchema
                    report_sha256=Get-BytesSha256 $reportBytes; report_size_bytes=[long]$reportBytes.Length
                    binding_sha256=Get-BytesSha256 $bindingBytes; binding_size_bytes=[long]$bindingBytes.Length
                    signing_request_sha256=Get-BytesSha256 $requestBytes
                    signing_request_size_bytes=[long]$requestBytes.Length
                    supervisor_receipt_sha256=$receiptInput.sha256
                    supervisor_receipt_size_bytes=[long]$receiptInput.size
                    raw_event_sha256=$rawEventEvidence.sha256; raw_event_size_bytes=$rawEventEvidence.size
                    callback_ledger_sha256=$ledgerEvidence.sha256
                    callback_ledger_size_bytes=$ledgerEvidence.size
                    source_mode=$report.source_mode; source_commit=$expectedSourceCommit
                    product_version=$ProductVersion; release_eligible=$false; fixture=$false; committed=$true
                }
                $commitRaw = $commit | ConvertTo-Json -Depth 5
                Assert-SanitizedEvidence $commitRaw
                Write-AtomicEvidenceBytes (Join-Path $runRoot 'commit.json') `
                    ([Text.UTF8Encoding]::new($false).GetBytes($commitRaw))
            } finally { $receiptInput.stream.Dispose() }
            $null = Assert-VulcanV3Package $runRoot $v3TrustRootEvidence `
                $ExpectedSupervisorTrustRootSha256 $v3ApprovedPin $expectedSourceCommit `
                $expectedVulcan $expectedPaper $expectedMCAce -RequireCurrentlyValidReceipt
            Write-Output 'VULCAN_GENUINE_EVENT_V3_PASS|external-supervisor-receipt-verified'
            return
        } finally {
            $ledgerEvidence.stream.Dispose()
            $rawEventEvidence.stream.Dispose()
        }
    }
    $report = [ordered]@{
        schema = $reportSchema
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        source_mode = 'EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED'
        source_commit = $expectedSourceCommit
        product_version = $ProductVersion
        release_eligible = $false
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
        observer_auth_protocol = $observer.auth_protocol
        observer_challenge_signature_verified = $observer.challenge_signature_verified
        observer_challenge_exchange_count = [int]$observer.challenge_exchange_count
        observer_access_token_run_bound = $observer.token_binding_verified_count -eq 1
        observer_event_causality_verified = $matched.event_causality_verified
        observer_distinct_event_count = [int]$observer.seen_event_ids.Count
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
            'NETWORK_ISOLATION_OPERATOR_ATTESTED_NOT_OS_VERIFIED_BY_SCRIPT',
            'OBSERVER_CLIENT_IDENTITY_USES_PUBLIC_RFC8032_TEST_VECTOR_NOT_EXTERNAL_TRUST_ANCHOR',
            'OPERATOR_ATTESTED_V2_EVIDENCE_NOT_RELEASE_ELIGIBLE_WITHOUT_EXTERNAL_PINNED_SUPERVISOR_RECEIPT')
        passed = $true
    }
    $reportRaw = $report | ConvertTo-Json -Depth 6
    Assert-SanitizedEvidence $reportRaw
    $reportBytes = [Text.UTF8Encoding]::new($false).GetBytes($reportRaw)
    $reportPath = Join-Path $runRoot 'report.json'
    Write-AtomicEvidenceBytes $reportPath $reportBytes
    $binding = [ordered]@{
        schema = $bindingSchema
        report_schema = $reportSchema
        report_generated_at = $report.generated_at
        report_sha256 = Get-BytesSha256 $reportBytes
        report_size_bytes = [long]$reportBytes.Length
        source_mode = 'EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED'
        source_commit = $expectedSourceCommit
        product_version = $ProductVersion
        release_eligible = $false
        vulcan_sha256 = $expectedVulcan
        paper_sha256 = $expectedPaper
        mcace_sha256 = $expectedMCAce
        vulcan_size = [long]$lockedVulcan.length
        paper_size = [long]$lockedPaper.length
        mcace_size = [long]$lockedMCAce.length
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
    $bindingBytes = [Text.UTF8Encoding]::new($false).GetBytes($bindingRaw)
    Write-AtomicEvidenceBytes (Join-Path $runRoot 'binding.json') $bindingBytes
    $commit = [ordered]@{
        schema = $commitSchema
        generated_at = $report.generated_at
        report_schema = $reportSchema
        binding_schema = $bindingSchema
        report_generated_at = $report.generated_at
        report_sha256 = Get-BytesSha256 $reportBytes
        report_size_bytes = [long]$reportBytes.Length
        binding_sha256 = Get-BytesSha256 $bindingBytes
        binding_size_bytes = [long]$bindingBytes.Length
        source_mode = 'EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED'
        source_commit = $expectedSourceCommit
        product_version = $ProductVersion
        release_eligible = $false
        committed = $true
    }
    $commitRaw = $commit | ConvertTo-Json -Depth 4
    Assert-SanitizedEvidence $commitRaw
    $commitBytes = [Text.UTF8Encoding]::new($false).GetBytes($commitRaw)
    Write-AtomicEvidenceBytes (Join-Path $runRoot 'commit.json') $commitBytes
    $null = Assert-EvidenceTriplet `
        $reportPath $expectedVulcan $expectedPaper $expectedMCAce $expectedPrepared `
        $expectedSourceCommit $ProductVersion
    Write-Output 'VULCAN_GENUINE_EVENT_PASS|sanitized-report-retained'
} finally {
    Stop-LoopbackObserver $observer
    if ($null -ne $v3TrustRootEvidence -and $null -ne $v3TrustRootEvidence.stream) {
        $v3TrustRootEvidence.stream.Dispose()
    }
    if ($null -ne $lockedMCAce) { $lockedMCAce.stream.Dispose() }
    if ($null -ne $lockedPaper) { $lockedPaper.stream.Dispose() }
    if ($null -ne $lockedVulcan) { $lockedVulcan.stream.Dispose() }
}
