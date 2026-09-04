[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Federation', 'Vulcan', 'ProductionAuthority')]
    [string]$Gate,

    [Parameter(Mandatory = $true)]
    [string]$ReportPath,

    [Parameter(Mandatory = $true)]
    [string]$BindingPath,

    [string]$CommitPath,

    [Parameter(Mandatory = $true)]
    [string]$SourceCommit,

    [string]$EvidenceId,

    [string]$VisibleGuiTrustRootPath,

    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedVisibleGuiTrustRootSha256,

    [string]$PostRunSupervisorTrustRootPath,

    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPostRunSupervisorTrustRootSha256,

    [string]$VulcanSupervisorTrustRootPath,

    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedVulcanSupervisorTrustRootSha256,

    [string]$ReleaseBundleRoot,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$evidenceRootRelative = 'docs/evidence'
$evidenceRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot $evidenceRootRelative))
$utf8Strict = New-Object Text.UTF8Encoding($false, $true)
$utf8NoBom = New-Object Text.UTF8Encoding($false)
$maximumNativeJsonBytes = 2097152
$maximumNativeBinaryBytes = 20971520
$maximumAuthorityArtifactBytes = 134217728
$reviewedVulcanSha256 = '7ee3a4fdd7e9da5269f9efc327478e507563e6e7df7abec2222acd3b499bc993'
$reviewedVulcanSize = 3820392

function Test-Sha256([object]$Value) {
    return $Value -is [string] -and [string]$Value -cmatch '^[0-9a-f]{64}$'
}

function Test-Commit([object]$Value) {
    return $Value -is [string] -and [string]$Value -cmatch '^[0-9a-f]{40}$'
}

function Test-NonEmptyJsonString([object]$Value) {
    return $Value -is [string] -and -not [string]::IsNullOrWhiteSpace([string]$Value)
}

function Test-True([object]$Value) {
    return $Value -is [bool] -and [bool]$Value
}

function Test-False([object]$Value) {
    return $Value -is [bool] -and -not [bool]$Value
}

function Test-JsonInteger([object]$Value) {
    return $Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64]
}

function Test-JsonArray([object]$Value) { return $Value -is [Array] }

function Test-ExactProperties([object]$Value, [string[]]$Expected) {
    if ($null -eq $Value -or $Value -isnot [Management.Automation.PSCustomObject]) { return $false }
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Expected.Count) { return $false }
    $actualSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $actual) { if (-not $actualSet.Add([string]$name)) { return $false } }
    foreach ($name in $Expected) { if (-not $actualSet.Contains($name)) { return $false } }
    return $true
}

function Test-StringEqual([object]$Value, [string]$Expected) {
    return $Value -is [string] -and [string]$Value -ceq $Expected
}

function Get-BytesSha256([byte[]]$Bytes) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
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
        if (@($names | Group-Object { $_.ToLowerInvariant() } | Where-Object Count -gt 1).Count -gt 0) {
            throw 'MCACE_NATIVE_EVIDENCE_JSON_CASE_AMBIGUOUS_PROPERTY'
        }
        foreach ($key in @($Value.Keys)) { Assert-NoCaseAmbiguousJsonProperties $Value[$key] }
        return
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $properties = @($Value.PSObject.Properties)
        $names = @($properties | ForEach-Object Name)
        if (@($names | Group-Object { $_.ToLowerInvariant() } | Where-Object Count -gt 1).Count -gt 0) {
            throw 'MCACE_NATIVE_EVIDENCE_JSON_CASE_AMBIGUOUS_PROPERTY'
        }
        foreach ($property in $properties) { Assert-NoCaseAmbiguousJsonProperties $property.Value }
        return
    }
    if ($Value -is [Collections.IEnumerable]) {
        foreach ($item in $Value) { Assert-NoCaseAmbiguousJsonProperties $item }
    }
}

function Assert-NoSecretBearingJsonProperties([object]$Value) {
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return }
    $forbidden = @('password','passwd','secret','token','private_key','private_key_pem','credential',
        'credentials','authorization','cookie','api_key','access_key','client_secret')
    if ($Value -is [Collections.IDictionary]) {
        foreach ($key in @($Value.Keys)) {
            if ([string]$key -in $forbidden) { throw "MCACE_NATIVE_EVIDENCE_SECRET_FIELD_REJECTED|$key" }
            Assert-NoSecretBearingJsonProperties $Value[$key]
        }
        return
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        foreach ($property in @($Value.PSObject.Properties)) {
            if ([string]$property.Name -in $forbidden) { throw "MCACE_NATIVE_EVIDENCE_SECRET_FIELD_REJECTED|$($property.Name)" }
            Assert-NoSecretBearingJsonProperties $property.Value
        }
        return
    }
    if ($Value -is [Collections.IEnumerable]) {
        foreach ($item in $Value) { Assert-NoSecretBearingJsonProperties $item }
    }
}

function ConvertFrom-StrictJsonRaw([string]$Raw) {
    if ([string]::IsNullOrWhiteSpace($Raw)) { throw 'MCACE_NATIVE_EVIDENCE_JSON_EMPTY' }
    $trimmed = $Raw.Trim()
    if ($trimmed.Length -lt 2 -or $trimmed[0] -cne '{' -or $trimmed[$trimmed.Length - 1] -cne '}') {
        throw 'MCACE_NATIVE_EVIDENCE_TOP_LEVEL_OBJECT_REQUIRED'
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
        throw 'MCACE_NATIVE_EVIDENCE_DUPLICATE_OR_AMBIGUOUS_PROPERTY'
    }
    Assert-NoCaseAmbiguousJsonProperties $value
    Assert-NoSecretBearingJsonProperties $value
    return $value
}

function Assert-SanitizedNativeJsonRaw([string]$Raw, [string]$Role) {
    # The Vulcan V2 diagnostic schema contains the boolean contract name
    # `observer_access_token_run_bound`; it is not token material.  Remove only
    # that exact JSON property token before the generic secret-text scan so any
    # other access-token key/value or embedded credential remains rejected.
    $secretScan = [regex]::Replace(
        $Raw,
        '(?i)"observer_access_token_run_bound"(?=\s*:)',
        '"observer_run_bound"')
    if ($Raw -match '(?i)[A-Z]:[\\/]|\\\\|(?:^|["\s])/(?!/)[^"\r\n]*' -or
            $secretScan -match '(?i)private.?key|client.?secret|access.?token|raw.?grant|raw.?presentation') {
        throw "MCACE_NATIVE_EVIDENCE_SENSITIVE_OR_ABSOLUTE_VALUE_REJECTED|$Role"
    }
}

function Assert-PathChainNoReparse([string]$AbsolutePath, [bool]$LeafMustExist) {
    $full = [IO.Path]::GetFullPath($AbsolutePath)
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root)) { throw 'MCACE_NATIVE_EVIDENCE_PATH_ROOT_INVALID' }
    $relative = $full.Substring($root.Length)
    [char[]]$separators = @([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $segments = @($relative.Split($separators, [StringSplitOptions]::RemoveEmptyEntries))
    $cursor = $root
    for ($index = 0; $index -lt $segments.Count; $index++) {
        $cursor = Join-Path $cursor $segments[$index]
        if (-not (Test-Path -LiteralPath $cursor)) {
            if ($LeafMustExist -or $index -lt ($segments.Count - 1)) {
                throw "MCACE_NATIVE_EVIDENCE_PATH_COMPONENT_MISSING|$cursor"
            }
            return
        }
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($item.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $item.LinkType)) {
            throw "MCACE_NATIVE_EVIDENCE_REPARSE_PATH_REJECTED|$cursor"
        }
    }
}

function Test-NativeWindowsPlatform {
    if (Get-Variable IsWindows -ErrorAction SilentlyContinue) { return [bool]$IsWindows }
    return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

function Initialize-NativeFileIdentityApi {
    if (-not (Test-NativeWindowsPlatform) -or
            ('MCAceNativeEvidenceFileIdentityV2' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class MCAceNativeEvidenceFileIdentityV2 {
    private const uint FILE_READ_ATTRIBUTES = 0x80;
    private const uint FILE_SHARE_READ = 0x1;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    [StructLayout(LayoutKind.Sequential)]
    private struct INFO {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks;
        public uint FileIndexHigh, FileIndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out INFO info);
    private static string Describe(INFO i) {
        return i.VolumeSerialNumber.ToString("x8") + ":" +
            i.FileIndexHigh.ToString("x8") + i.FileIndexLow.ToString("x8");
    }
    public static string NoFollow(string path, bool directory) {
        uint flags = FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0u);
        using (SafeFileHandle h = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero)) {
            if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            INFO i; if (!GetFileInformationByHandle(h, out i))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((i.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                throw new InvalidOperationException("reparse point rejected");
            return Describe(i);
        }
    }
    public static string FromHandle(SafeFileHandle h) {
        INFO i; if (!GetFileInformationByHandle(h, out i))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if ((i.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            throw new InvalidOperationException("reparse point rejected");
        return Describe(i);
    }
}
'@
}

function Get-NativeNoFollowFileIdentity([string]$Path, [switch]$Directory) {
    if (Test-NativeWindowsPlatform) {
        Initialize-NativeFileIdentityApi
        try { return [MCAceNativeEvidenceFileIdentityV2]::NoFollow($Path, [bool]$Directory) }
        catch { throw "MCACE_NATIVE_EVIDENCE_NOFOLLOW_IDENTITY_FAILED|$($_.Exception.Message)" }
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($item.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $item.LinkType)) {
        throw 'MCACE_NATIVE_EVIDENCE_REPARSE_IDENTITY_REJECTED'
    }
    return "portable:$($item.FullName):$([long]$item.Length):$($item.LastWriteTimeUtc.Ticks)"
}

function Assert-NativeLockedFileIdentity(
        [string]$Path,
        [IO.FileStream]$Stream,
        [string]$Before) {
    if (Test-NativeWindowsPlatform) {
        try { $handle = [MCAceNativeEvidenceFileIdentityV2]::FromHandle($Stream.SafeFileHandle) }
        catch { throw "MCACE_NATIVE_EVIDENCE_HANDLE_IDENTITY_FAILED|$($_.Exception.Message)" }
        if ($handle -cne $Before) { throw 'MCACE_NATIVE_EVIDENCE_HANDLE_IDENTITY_CHANGED' }
    }
    if ((Get-NativeNoFollowFileIdentity $Path) -cne $Before) {
        throw 'MCACE_NATIVE_EVIDENCE_PATH_IDENTITY_CHANGED'
    }
}

function ConvertTo-InputAbsolutePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'MCACE_NATIVE_EVIDENCE_INPUT_PATH_REQUIRED' }
    $candidate = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else {
        if ($Path.Contains('..')) { throw 'MCACE_NATIVE_EVIDENCE_INPUT_PATH_TRAVERSAL_REJECTED' }
        [IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
    }
    Assert-PathChainNoReparse $candidate $true
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "MCACE_NATIVE_EVIDENCE_INPUT_FILE_REQUIRED|$candidate"
    }
    return $candidate
}

function Read-NativeJson([string]$Path, [string]$Role) {
    $absolute = ConvertTo-InputAbsolutePath $Path
    $identityBefore = Get-NativeNoFollowFileIdentity $absolute
    $stream = New-Object IO.FileStream($absolute, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $length = $stream.Length
        if ($length -le 0 -or $length -gt $maximumNativeJsonBytes) {
            throw "MCACE_NATIVE_EVIDENCE_SIZE_INVALID|$Role|$length"
        }
        $bytes = New-Object byte[] ([int]$length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw "MCACE_NATIVE_EVIDENCE_SHORT_READ|$Role" }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1 -or $stream.Length -ne $length) {
            throw "MCACE_NATIVE_EVIDENCE_CHANGED_DURING_READ|$Role"
        }
        Assert-NativeLockedFileIdentity $absolute $stream $identityBefore
    } finally {
        $stream.Dispose()
    }
    Assert-PathChainNoReparse $absolute $true
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        throw "MCACE_NATIVE_EVIDENCE_UTF8_BOM_REJECTED|$Role"
    }
    $raw = $utf8Strict.GetString($bytes)
    $value = ConvertFrom-StrictJsonRaw $raw
    Assert-SanitizedNativeJsonRaw $raw $Role
    return [pscustomobject]@{
        role = $Role
        absolute = $absolute
        bytes = $bytes
        raw = $raw
        size = [long]$bytes.Length
        size_bytes = [long]$bytes.Length
        sha256 = Get-BytesSha256 $bytes
        value = $value
    }
}

function Read-NativeBinary([string]$Path, [string]$Role) {
    $absolute = ConvertTo-InputAbsolutePath $Path
    $identityBefore = Get-NativeNoFollowFileIdentity $absolute
    $stream = New-Object IO.FileStream($absolute, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $length = $stream.Length
        if ($length -lt 128 -or $length -gt $maximumNativeBinaryBytes) {
            throw "MCACE_NATIVE_EVIDENCE_BINARY_SIZE_INVALID|$Role|$length"
        }
        $bytes = New-Object byte[] ([int]$length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw "MCACE_NATIVE_EVIDENCE_SHORT_READ|$Role" }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1 -or $stream.Length -ne $length) {
            throw "MCACE_NATIVE_EVIDENCE_CHANGED_DURING_READ|$Role"
        }
        Assert-NativeLockedFileIdentity $absolute $stream $identityBefore
    } finally {
        $stream.Dispose()
    }
    Assert-PathChainNoReparse $absolute $true
    return [pscustomobject]@{
        role = $Role
        absolute = $absolute
        bytes = $bytes
        size = [long]$bytes.Length
        size_bytes = [long]$bytes.Length
        sha256 = Get-BytesSha256 $bytes
    }
}

function Read-AuthorityLockedOpaqueFile(
        [string]$Path,
        [string]$Role,
        [long]$MaximumBytes = 0L) {
    if ($MaximumBytes -le 0) { $MaximumBytes = $maximumAuthorityArtifactBytes }
    $absolute = ConvertTo-InputAbsolutePath $Path
    $identityBefore = Get-NativeNoFollowFileIdentity $absolute
    $stream = New-Object IO.FileStream($absolute, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        $length = [long]$stream.Length
        if ($length -le 0 -or $length -gt $MaximumBytes -or $length -gt [int]::MaxValue) {
            throw "MCACE_NATIVE_EVIDENCE_AUTHORITY_FILE_SIZE_INVALID|$Role|$length"
        }
        [byte[]]$first = New-Object byte[] ([int]$length)
        $offset = 0
        while ($offset -lt $first.Length) {
            $read = $stream.Read($first,$offset,$first.Length-$offset)
            if ($read -le 0) { throw "MCACE_NATIVE_EVIDENCE_AUTHORITY_SHORT_READ|$Role|first" }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1) {
            throw "MCACE_NATIVE_EVIDENCE_AUTHORITY_GROWTH_DURING_READ|$Role|first"
        }
        $stream.Position = 0L
        [byte[]]$second = New-Object byte[] ([int]$length)
        $offset = 0
        while ($offset -lt $second.Length) {
            $read = $stream.Read($second,$offset,$second.Length-$offset)
            if ($read -le 0) { throw "MCACE_NATIVE_EVIDENCE_AUTHORITY_SHORT_READ|$Role|second" }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1 -or $stream.Length -ne $length -or
                (Get-BytesSha256 $first) -cne (Get-BytesSha256 $second)) {
            throw "MCACE_NATIVE_EVIDENCE_AUTHORITY_LOCKED_DOUBLE_READ_MISMATCH|$Role"
        }
        Assert-NativeLockedFileIdentity $absolute $stream $identityBefore
    } finally { $stream.Dispose() }
    Assert-PathChainNoReparse $absolute $true
    if ((Get-NativeNoFollowFileIdentity $absolute) -cne $identityBefore) {
        throw "MCACE_NATIVE_EVIDENCE_AUTHORITY_PATH_IDENTITY_CHANGED|$Role"
    }
    return [pscustomobject]@{
        role=$Role; absolute=$absolute; bytes=$first; size=[long]$first.Length
        size_bytes=[long]$first.Length; sha256=(Get-BytesSha256 $first)
    }
}

function Read-AuthorityLockedJson([string]$Path, [string]$Role) {
    $document = Read-AuthorityLockedOpaqueFile $Path $Role $maximumNativeJsonBytes
    if ($document.bytes.Length -ge 3 -and $document.bytes[0] -eq 0xEF -and
            $document.bytes[1] -eq 0xBB -and $document.bytes[2] -eq 0xBF) {
        throw "MCACE_NATIVE_EVIDENCE_AUTHORITY_UTF8_BOM_REJECTED|$Role"
    }
    $raw = $utf8Strict.GetString($document.bytes)
    if ($raw.Contains("`r") -or -not $raw.EndsWith("`n")) {
        throw "MCACE_NATIVE_EVIDENCE_AUTHORITY_CANONICAL_JSON_REQUIRED|$Role"
    }
    $value = ConvertFrom-StrictJsonRaw $raw
    $document | Add-Member NoteProperty raw $raw
    $document | Add-Member NoteProperty value $value
    return $document
}

function Get-NativeReleaseBundleBinding([string]$Root, [string]$ExpectedArtifactSourceCommit) {
    if ([string]::IsNullOrWhiteSpace($Root)) {
        throw 'MCACE_NATIVE_EVIDENCE_RELEASE_BUNDLE_REQUIRED'
    }
    $resolvedRoot = if ([IO.Path]::IsPathRooted($Root)) {
        [IO.Path]::GetFullPath($Root)
    } else { [IO.Path]::GetFullPath((Join-Path $repoRoot $Root)) }
    Assert-PathChainNoReparse $resolvedRoot $true
    if (-not (Test-Path -LiteralPath $resolvedRoot -PathType Container)) {
        throw 'MCACE_NATIVE_EVIDENCE_RELEASE_BUNDLE_DIRECTORY_REQUIRED'
    }
    $expectedNames = @('SHA256SUMS','release-manifest.properties',
        'mcace-client-fabric-1.21.11.jar','mcace-client-fabric-26.1.2.jar',
        'mcace-client-fabric-26.2.jar','mcace-server-velocity.jar',
        'mcace-server-bungeecord.jar','mcace-server-paper.jar')
    $entries = @(Get-ChildItem -LiteralPath $resolvedRoot -Force -ErrorAction Stop)
    if ($entries.Count -ne 8 -or
            ((@($entries.Name | Sort-Object) -join '|') -cne
                (($expectedNames | Sort-Object) -join '|'))) {
        throw 'MCACE_NATIVE_EVIDENCE_RELEASE_BUNDLE_FILE_SET_INVALID'
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or
                ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($entry.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $entry.LinkType)) {
            throw 'MCACE_NATIVE_EVIDENCE_RELEASE_BUNDLE_ENTRY_TYPE_INVALID'
        }
    }
    $manifestDoc = Read-NativeBinary (Join-Path $resolvedRoot 'release-manifest.properties') `
        'release-manifest'
    $sumsDoc = Read-NativeBinary (Join-Path $resolvedRoot 'SHA256SUMS') 'release-sha256sums'
    foreach ($doc in @($manifestDoc,$sumsDoc)) {
        if ($doc.bytes.Length -ge 3 -and $doc.bytes[0] -eq 0xEF -and
                $doc.bytes[1] -eq 0xBB -and $doc.bytes[2] -eq 0xBF) {
            throw 'MCACE_NATIVE_EVIDENCE_RELEASE_BUNDLE_UTF8_BOM_REJECTED'
        }
    }
    $manifestRaw = $utf8Strict.GetString($manifestDoc.bytes)
    $sumsRaw = $utf8Strict.GetString($sumsDoc.bytes)
    if ($manifestRaw.Contains("`r") -or -not $manifestRaw.EndsWith("`n") -or
            $sumsRaw.Contains("`r") -or -not $sumsRaw.EndsWith("`n")) {
        throw 'MCACE_NATIVE_EVIDENCE_RELEASE_BUNDLE_CANONICAL_ENCODING_INVALID'
    }
    $manifestMap = [ordered]@{}
    foreach ($line in @($manifestRaw.TrimEnd("`n") -split "`n")) {
        if ($line.Length -eq 0 -or $line -cne $line.Trim()) {
            throw 'MCACE_NATIVE_EVIDENCE_RELEASE_BUNDLE_MANIFEST_LINE_INVALID'
        }
        $separator = $line.IndexOf('=')
        if ($separator -lt 1) { throw 'MCACE_NATIVE_EVIDENCE_RELEASE_BUNDLE_MANIFEST_LINE_INVALID' }
        $key = $line.Substring(0,$separator)
        $value = $line.Substring($separator + 1)
        if ($key -cnotmatch '^[A-Za-z0-9._-]+$' -or $manifestMap.Contains($key)) {
            throw 'MCACE_NATIVE_EVIDENCE_RELEASE_BUNDLE_MANIFEST_KEY_INVALID'
        }
        $manifestMap[$key] = $value
    }
    $jarNames = @($expectedNames | Where-Object { $_.EndsWith('.jar',[StringComparison]::Ordinal) })
    $manifestNames = @('schema','bundle_profile','release_identity','deployable_count',
        'bundle_entry_count','product_version','source_commit','artifact_source_commit',
        'root_java_version','root_java_specification_version','root_gradle_version',
        'modern_java_version','modern_java_specification_version','modern_gradle_version')
    foreach ($jarName in $jarNames) {
        $key = $jarName.Remove($jarName.Length - 4).Replace('-', '_').Replace('.', '_')
        $manifestNames += "artifact.$key.file"
        $manifestNames += "artifact.$key.sha256"
        if ($jarName.StartsWith('mcace-client-fabric-', [StringComparison]::Ordinal)) {
            $manifestNames += "artifact.$key.minecraft_version"
            $manifestNames += "artifact.$key.client_build_id"
        }
    }
    $manifest = [pscustomobject]$manifestMap
    if (-not (Test-ExactProperties $manifest $manifestNames) -or
            [string]$manifest.schema -cne 'MCACE_RELEASE_BUNDLE_V4' -or
            [string]$manifest.bundle_profile -cne 'RELEASE' -or
            [string]$manifest.release_identity -cne 'true' -or
            [string]$manifest.deployable_count -cne '6' -or
            [string]$manifest.bundle_entry_count -cne '8' -or
            [string]$manifest.product_version -cne '0.0.1' -or
            [string]$manifest.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
            [string]$manifest.artifact_source_commit -cne $ExpectedArtifactSourceCommit) {
        throw 'MCACE_NATIVE_EVIDENCE_RELEASE_BUNDLE_MANIFEST_INVALID'
    }
    $sumLines = @($sumsRaw.TrimEnd("`n") -split "`n")
    if ($sumLines.Count -ne 6) {
        throw 'MCACE_NATIVE_EVIDENCE_RELEASE_BUNDLE_SHA256SUMS_INVALID'
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $artifacts = [ordered]@{}
    foreach ($line in $sumLines) {
        if ($line -cnotmatch '^(?<sha>[0-9a-f]{64})  (?<file>[A-Za-z0-9][A-Za-z0-9._-]*\.jar)$' -or
                $Matches.file -cnotin $jarNames -or -not $seen.Add($Matches.file)) {
            throw 'MCACE_NATIVE_EVIDENCE_RELEASE_BUNDLE_SHA256SUMS_INVALID'
        }
        # Any nested regex in the locked-read helpers may replace PowerShell's dynamic $Matches
        # variable, so capture the canonical sum fields before crossing that call boundary.
        $sumFile = [string]$Matches.file
        $sumSha256 = [string]$Matches.sha
        $jarDoc = Read-NativeBinary (Join-Path $resolvedRoot $sumFile) 'release-bundle-jar'
        $key = $sumFile.Remove($sumFile.Length - 4).Replace('-', '_').Replace('.', '_')
        if ($jarDoc.sha256 -cne $sumSha256 -or
                [string]$manifest."artifact.$key.file" -cne $sumFile -or
                [string]$manifest."artifact.$key.sha256" -cne $sumSha256) {
            throw 'MCACE_NATIVE_EVIDENCE_RELEASE_BUNDLE_ARTIFACT_BINDING_INVALID'
        }
        if ($sumFile -cmatch '^mcace-client-fabric-(?<target>1\.21\.11|26\.1\.2|26\.2)\.jar$' -and
                ([string]$manifest."artifact.$key.minecraft_version" -cne $Matches.target -or
                 [string]$manifest."artifact.$key.client_build_id" -cne
                    "fabric-$($Matches.target)-$ExpectedArtifactSourceCommit")) {
            throw 'MCACE_NATIVE_EVIDENCE_RELEASE_BUNDLE_CLIENT_IDENTITY_INVALID'
        }
        $artifacts[$sumFile] = [pscustomobject]@{
            file=$sumFile; sha256=$jarDoc.sha256; size_bytes=[long]$jarDoc.size_bytes
        }
    }
    if ($seen.Count -ne 6) { throw 'MCACE_NATIVE_EVIDENCE_RELEASE_BUNDLE_SHA256SUMS_INVALID' }
    return [pscustomobject]@{
        root=$resolvedRoot; manifest_sha256=$manifestDoc.sha256
        source_commit=[string]$manifest.source_commit
        artifact_source_commit=[string]$manifest.artifact_source_commit
        product_version=[string]$manifest.product_version
        artifacts=[pscustomobject]$artifacts
    }
}

function Get-PngUInt32([byte[]]$Bytes, [int]$Offset) {
    if ($Offset -lt 0 -or $Offset + 4 -gt $Bytes.Length) {
        throw 'MCACE_NATIVE_EVIDENCE_PNG_TRUNCATED'
    }
    return [uint32](([uint32]$Bytes[$Offset] -shl 24) -bor
        ([uint32]$Bytes[$Offset + 1] -shl 16) -bor
        ([uint32]$Bytes[$Offset + 2] -shl 8) -bor [uint32]$Bytes[$Offset + 3])
}

function Assert-Png([object]$Document) {
    $signature = [byte[]](0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a)
    if ($Document.bytes.Length -lt 33) { throw 'MCACE_NATIVE_EVIDENCE_PNG_TRUNCATED' }
    for ($index = 0; $index -lt $signature.Length; $index++) {
        if ($Document.bytes[$index] -ne $signature[$index]) {
            throw 'MCACE_NATIVE_EVIDENCE_PNG_SIGNATURE_INVALID'
        }
    }
    if ((Get-PngUInt32 $Document.bytes 8) -ne 13 -or
            [Text.Encoding]::ASCII.GetString($Document.bytes, 12, 4) -cne 'IHDR') {
        throw 'MCACE_NATIVE_EVIDENCE_PNG_IHDR_INVALID'
    }
    $width = [long](Get-PngUInt32 $Document.bytes 16)
    $height = [long](Get-PngUInt32 $Document.bytes 20)
    if ($width -lt 320 -or $width -gt 16384 -or $height -lt 200 -or $height -gt 16384) {
        throw 'MCACE_NATIVE_EVIDENCE_PNG_DIMENSIONS_INVALID'
    }
    return [pscustomobject]@{ width = [int]$width; height = [int]$height }
}

function Get-RequiredProperty([object]$Value, [string]$Name, [string]$Role) {
    if ($null -eq $Value -or -not ($Value.PSObject.Properties.Name -ccontains $Name)) {
        throw "MCACE_NATIVE_EVIDENCE_REQUIRED_PROPERTY_MISSING|$Role|$Name"
    }
    return $Value.PSObject.Properties[$Name].Value
}

function Assert-EvidenceTime([object]$Value, [string]$Role) {
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        throw "MCACE_NATIVE_EVIDENCE_TIMESTAMP_INVALID|$Role"
    }
    $parsed = [DateTimeOffset]::MinValue
    $roundTrip = [DateTimeOffset]::TryParseExact(
            [string]$Value,
            'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None,
            [ref]$parsed)
    $authorityCanonical = $false
    if (-not $roundTrip -and [string]$Value -cmatch
            '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3,7})?Z$') {
        $authorityCanonical = [DateTimeOffset]::TryParse([string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$parsed)
    }
    if (-not $roundTrip -and -not $authorityCanonical) {
        throw "MCACE_NATIVE_EVIDENCE_TIMESTAMP_INVALID|$Role"
    }
    return $parsed.ToUniversalTime()
}

function Assert-SameEvidenceTime([object]$Left, [object]$Right, [string]$Role) {
    $leftTime = Assert-EvidenceTime $Left "$Role-left"
    $rightTime = Assert-EvidenceTime $Right "$Role-right"
    if ($leftTime.ToUniversalTime().Ticks -ne $rightTime.ToUniversalTime().Ticks) {
        throw "MCACE_NATIVE_EVIDENCE_TIMESTAMP_MISMATCH|$Role"
    }
}

function Assert-Schema([object]$Value, [object]$Expected, [string]$Role) {
    $actual = Get-RequiredProperty $Value 'schema' $Role
    if ($Expected -is [int]) {
        if (($actual -isnot [byte] -and $actual -isnot [int16] -and $actual -isnot [int32] -and $actual -isnot [int64]) -or
                [int64]$actual -ne [int64]$Expected) {
            throw "MCACE_NATIVE_EVIDENCE_SCHEMA_INVALID|$Role"
        }
    } elseif (-not (Test-StringEqual $actual ([string]$Expected))) {
        throw "MCACE_NATIVE_EVIDENCE_SCHEMA_INVALID|$Role"
    }
}

function Assert-ReportHashBinding([object]$Binding, [object]$ReportDoc) {
    $reportHash = Get-RequiredProperty $Binding 'report_sha256' 'binding'
    if (-not (Test-Sha256 $reportHash) -or [string]$reportHash -cne [string]$ReportDoc.sha256) {
        throw 'MCACE_NATIVE_EVIDENCE_REPORT_HASH_MISMATCH'
    }
}

function Assert-CommitHashBinding([object]$Commit, [object]$ReportDoc, [object]$BindingDoc) {
    $reportHash = Get-RequiredProperty $Commit 'report_sha256' 'commit'
    $bindingHash = Get-RequiredProperty $Commit 'binding_sha256' 'commit'
    if (-not (Test-Sha256 $reportHash) -or [string]$reportHash -cne [string]$ReportDoc.sha256 -or
            -not (Test-Sha256 $bindingHash) -or [string]$bindingHash -cne [string]$BindingDoc.sha256) {
        throw 'MCACE_NATIVE_EVIDENCE_COMMIT_HASH_MISMATCH'
    }
}

function Assert-RequiredTrue([object]$Value, [string]$Name, [string]$Role) {
    if (-not (Test-True (Get-RequiredProperty $Value $Name $Role))) {
        throw "MCACE_NATIVE_EVIDENCE_REQUIRED_TRUE|$Role|$Name"
    }
}

function New-Descriptor([string]$RelativePath, [object]$Document) {
    return [pscustomobject][ordered]@{
        path = $RelativePath
        sha256 = [string]$Document.sha256
        size_bytes = [long]$Document.size
    }
}

function Get-NativeAstFunctionText(
        [Management.Automation.Language.Ast]$Root,
        [string[]]$Names) {
    $parts = [Collections.Generic.List[string]]::new()
    foreach ($name in $Names) {
        $matches = @($Root.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $name
        }, $true))
        if ($matches.Count -ne 1) {
            throw "MCACE_NATIVE_EVIDENCE_FEDERATION_VALIDATOR_FUNCTION_INVALID|$name"
        }
        $parts.Add($matches[0].Extent.Text)
    }
    return $parts -join "`n`n"
}

function Get-NativeAstAssignmentText(
        [Management.Automation.Language.Ast]$Root,
        [string]$VariableText) {
    $matches = @($Root.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq $VariableText
    }, $true))
    if ($matches.Count -ne 1) {
        throw "MCACE_NATIVE_EVIDENCE_FEDERATION_VALIDATOR_ASSIGNMENT_INVALID|$VariableText"
    }
    return $matches[0].Right.Extent.Text
}

function New-FederationV5ValidatorModule {
    $wrapper = Join-Path $PSScriptRoot 'fabric-federation-gui-handoff-smoke.ps1'
    $platform = Join-Path $PSScriptRoot 'platform-load-smoke.ps1'
    $wrapperTokens = $null; $wrapperErrors = $null
    $platformTokens = $null; $platformErrors = $null
    $wrapperAst = [Management.Automation.Language.Parser]::ParseFile(
        $wrapper, [ref]$wrapperTokens, [ref]$wrapperErrors)
    $platformAst = [Management.Automation.Language.Parser]::ParseFile(
        $platform, [ref]$platformTokens, [ref]$platformErrors)
    if (@($wrapperErrors).Count -ne 0 -or @($platformErrors).Count -ne 0) {
        throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_VALIDATOR_PARSE_FAILED'
    }
    $platformFunctions = Get-NativeAstFunctionText $platformAst @(
        'Get-BytesSha256','Get-JsonPropertyNames','Test-ExactJsonProperties',
        'Test-JsonInteger','Assert-DirectLocalPath')
    $wrapperFunctions = Get-NativeAstFunctionText $wrapperAst @(
        'ConvertFrom-StrictJson','Test-IsWindowsPlatform','Initialize-WindowsFileIdentityApi',
        'Get-NoFollowFileIdentity','Assert-LockedFileIdentity','Open-LockedFileBytes',
        'Get-Crc32','Get-Adler32','Expand-PngZlib','Get-PaethPredictor','Get-PngUInt32',
        'Assert-PngEvidence','Test-JsonString','Test-JsonBoolean','Test-Sha256',
        'Assert-VisibleGuiSigningRequest','Get-VisibleGuiAttestationSigningPayload','Assert-VisibleGuiTrustRoot',
        'Test-RsaPkcs1Sha256Signature','Assert-VisibleGuiAttestation',
        'Get-ApprovedReleaseSignerPin','Get-PostRunReceiptSigningPayload',
        'Assert-PostRunSupervisorTrustRoot','Assert-DistinctFederationSignerRoots',
        'Assert-PostRunReceipt','Get-PostRunReceiptExpectedBinding',
        'Read-StrictPropertiesBytes','Get-ReleaseBundleTargetBinding',
        'Get-ProcessIncarnationId','Get-RuntimeEventSigningPayload','Assert-RuntimeLedgerBytes',
        'Assert-PassingReportRaw','Assert-BindingRaw','Assert-CommitRaw')
    $header = @"
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
`$visibleGuiSigningRequestSchema = 'MCACE_VISIBLE_GUI_SIGNING_REQUEST_V1'
`$visibleGuiSigningRequestDomain = 'MCACE_VISIBLE_GUI_SIGNING_REQUEST_CANONICAL_V1'
`$visibleGuiAttestationSchema = 'MCACE_VISIBLE_GUI_ATTESTATION_V3'
`$visibleGuiAttestationSigningDomain = 'MCACE_VISIBLE_GUI_ATTESTATION_SIGNING_V3'
`$visibleGuiTrustRootSchema = 'MCACE_VISIBLE_GUI_TRUST_ROOT_V1'
`$postRunReceiptSchema = 'MCACE_FABRIC_FEDERATION_POSTRUN_RECEIPT_V1'
`$postRunTrustRootSchema = 'MCACE_FEDERATION_POSTRUN_TRUST_ROOT_V1'
`$runtimeEventSchema = 'MCACE_FABRIC_FEDERATION_RUNTIME_EVENT_V1'
`$reportSchema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V5'
`$bindingSchema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V5'
`$commitSchema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V5'
`$artifactClass = 'sanitized-final-fabric-federation-gui-handoff-v5'
`$visibleGuiAttestationArtifactClass = 'EXTERNAL_OPERATOR_VISIBLE_GUI_ATTESTATION'
`$visibleGuiAttestationSourceMode = 'EXTERNAL_COMPUTER_USE_CAPTURE'
`$visibleGuiSigningRequestArtifactClass = 'RUNNER_GENERATED_VISIBLE_GUI_SIGNING_REQUEST'
`$visibleGuiSigningRequestSourceMode = 'LOCAL_NOFOLLOW_ATOMIC_EXCHANGE'
`$postRunReceiptArtifactClass = 'EXTERNAL_FEDERATION_POSTRUN_SUPERVISOR_RECEIPT'
`$visibleGuiSigningRequestPropertyNames = $(Get-NativeAstAssignmentText $wrapperAst '$visibleGuiSigningRequestPropertyNames')
`$visibleGuiAttestationPropertyNames = $(Get-NativeAstAssignmentText $wrapperAst '$visibleGuiAttestationPropertyNames')
`$visibleGuiTrustRootPropertyNames = $(Get-NativeAstAssignmentText $wrapperAst '$visibleGuiTrustRootPropertyNames')
`$postRunTrustRootPropertyNames = $(Get-NativeAstAssignmentText $wrapperAst '$postRunTrustRootPropertyNames')
`$postRunReceiptPropertyNames = $(Get-NativeAstAssignmentText $wrapperAst '$postRunReceiptPropertyNames')
`$runtimeEventPropertyNames = $(Get-NativeAstAssignmentText $wrapperAst '$runtimeEventPropertyNames')
`$reportPropertyNames = $(Get-NativeAstAssignmentText $wrapperAst '$reportPropertyNames')
`$fabricTargets = [ordered]@{
    '1.21.11' = [ordered]@{
        minecraft_version = '1.21.11'
        fabric_api_version = '0.141.6+1.21.11'
        java_major = 21
        artifact_kind = 'FINAL_REMAP_JAR'
        runtime_mode = 'LOOM_FINAL_REMAP_ARTIFACT'
    }
    '26.1.2' = [ordered]@{
        minecraft_version = '26.1.2'
        fabric_api_version = '0.155.2+26.1.2'
        java_major = 25
        artifact_kind = 'FINAL_NAMED_JAR'
        runtime_mode = 'LOOM_FINAL_NAMED_JAR_ARTIFACT'
    }
    '26.2' = [ordered]@{
        minecraft_version = '26.2'
        fabric_api_version = '0.157.0+26.2'
        java_major = 25
        artifact_kind = 'FINAL_NAMED_JAR'
        runtime_mode = 'LOOM_FINAL_NAMED_JAR_ARTIFACT'
    }
}

"@
    return New-Module -ScriptBlock ([scriptblock]::Create(
        $header + "`n" + $platformFunctions + "`n" + $wrapperFunctions))
}

function New-VulcanV3ValidatorModule {
    $wrapper = Join-Path $PSScriptRoot 'vulcan-genuine-event-smoke.ps1'
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile(
        $wrapper,[ref]$tokens,[ref]$errors)
    if (@($errors).Count -ne 0) {
        throw 'MCACE_NATIVE_EVIDENCE_VULCAN_V3_VALIDATOR_PARSE_FAILED'
    }
    $functions = Get-NativeAstFunctionText $ast @(
        'ConvertTo-Sha256','Get-BytesSha256','ConvertFrom-StrictUtcInstant',
        'Assert-DirectLocalPath','Assert-SanitizedEvidence','Test-JsonBoolean',
        'Test-JsonInteger','Test-JsonArray','Get-JsonGraphPropertyCount',
        'Assert-NoCaseAmbiguousJsonProperties',
        'ConvertFrom-StrictJsonRaw','Get-JsonPropertyNames','Test-ExactProperties',
        'Test-RsaPkcs1Sha256Signature','Get-VulcanV3ReceiptSigningPayload',
        'Assert-VulcanV3TrustRoot','Open-LockedVulcanV3Evidence',
        'Assert-VulcanV3RawRiskEvent','Assert-VulcanV3CallbackLedger',
        'Assert-VulcanV3Receipt','Assert-VulcanV3Package')
    $header = @"
Set-StrictMode -Version Latest
`$ErrorActionPreference='Stop'
`$expectedPluginVersion='2.9.0'
`$reviewedVulcanSha256='7ee3a4fdd7e9da5269f9efc327478e507563e6e7df7abec2222acd3b499bc993'
`$v3ReportSchema='MCACE_VULCAN_GENUINE_EVENT_REPORT_V3'
`$v3BindingSchema='MCACE_VULCAN_GENUINE_EVENT_BINDING_V3'
`$v3CommitSchema='MCACE_VULCAN_GENUINE_EVENT_COMMIT_V3'
`$v3SigningRequestSchema='MCACE_VULCAN_GENUINE_EVENT_SIGNING_REQUEST_V1'
`$v3ReceiptSchema='MCACE_VULCAN_GENUINE_EVENT_SUPERVISOR_RECEIPT_V1'
`$v3TrustRootSchema='MCACE_VULCAN_GENUINE_EVENT_SUPERVISOR_TRUST_ROOT_V1'
`$v3SigningDomain='MCACE-VULCAN-GENUINE-EVENT-SUPERVISOR-RECEIPT-V1'
`$v3ReceiptPropertyNames=$(Get-NativeAstAssignmentText $ast '$v3ReceiptPropertyNames')
"@
    return New-Module -ScriptBlock ([scriptblock]::Create($header+"`n"+$functions))
}

function Assert-SafeEvidenceId([string]$Value, [string]$Prefix) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 180 -or
            $Value -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or
            -not $Value.StartsWith(($Prefix + '-'), [StringComparison]::Ordinal)) {
        throw 'MCACE_NATIVE_EVIDENCE_ID_INVALID'
    }
}

function Enter-NativeEvidencePublishMutex {
    [byte[]]$identityBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        [IO.Path]::GetFullPath($repoRoot).ToLowerInvariant())
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $identity = ([BitConverter]::ToString($sha.ComputeHash($identityBytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    $mutex = [Threading.Mutex]::new($false, "mcace-native-evidence-publish-$identity")
    $acquired = $false
    try {
        try { $acquired = $mutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) {
            throw 'MCACE_NATIVE_EVIDENCE_CONCURRENT_PUBLICATION_REJECTED'
        }
        return $mutex
    } catch {
        if (-not $acquired) { $mutex.Dispose() }
        throw
    }
}

function Exit-NativeEvidencePublishMutex([Threading.Mutex]$Mutex) {
    if ($null -eq $Mutex) { return }
    try { $Mutex.ReleaseMutex() } finally { $Mutex.Dispose() }
}

function Assert-FederationNoPublicationReplay([object]$Candidate) {
    if (Test-Path -LiteralPath $evidenceRoot -PathType Container) {
        foreach ($existingPath in @(Get-ChildItem -LiteralPath $evidenceRoot -File -Force `
                -Filter 'federation-gui-handoff-*.json' -ErrorAction Stop)) {
            $existing = Read-NativeJson $existingPath.FullName 'existing-federation-v5-index'
            if ([string]$existing.value.schema -ceq
                    'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V5' -and
                    ([string]$existing.value.gui_attempt_id -ceq [string]$Candidate.gui_attempt_id -or
                     [string]$existing.value.gui_challenge_nonce -ceq [string]$Candidate.gui_challenge_nonce -or
                     [string]$existing.value.postrun_operation_attempt_id -ceq
                        [string]$Candidate.postrun_operation_attempt_id -or
                     [string]$existing.value.postrun_challenge_nonce -ceq
                        [string]$Candidate.postrun_challenge_nonce)) {
                throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_V5_REPLAY_REJECTED'
            }
        }
    }
}

function Get-SafeTimeToken([DateTimeOffset]$Time) {
    return $Time.ToUniversalTime().ToString('yyyyMMddTHHmmssfffffffZ', [Globalization.CultureInfo]::InvariantCulture)
}

function Assert-DestinationBaseSafe {
    Assert-PathChainNoReparse $repoRoot $true
    Assert-PathChainNoReparse (Split-Path -Parent $evidenceRoot) $true
    if (Test-Path -LiteralPath $evidenceRoot) {
        Assert-PathChainNoReparse $evidenceRoot $true
        if (-not (Test-Path -LiteralPath $evidenceRoot -PathType Container)) {
            throw 'MCACE_NATIVE_EVIDENCE_ROOT_DIRECTORY_REQUIRED'
        }
    } else {
        [void][IO.Directory]::CreateDirectory($evidenceRoot)
        Assert-PathChainNoReparse $evidenceRoot $true
    }
}

if (-not (Test-Commit $SourceCommit)) {
    throw 'MCACE_NATIVE_EVIDENCE_SOURCE_COMMIT_INVALID'
}
$SourceCommit = $SourceCommit.ToLowerInvariant()
& git -C $repoRoot cat-file -e "$SourceCommit`^{commit}" 2>$null
if ($LASTEXITCODE -ne 0) { throw 'MCACE_NATIVE_EVIDENCE_SOURCE_COMMIT_UNKNOWN' }

if ($Gate -ceq 'Federation') {
    if ([string]::IsNullOrWhiteSpace($VisibleGuiTrustRootPath) -or
            [string]::IsNullOrWhiteSpace($ExpectedVisibleGuiTrustRootSha256) -or
            [string]::IsNullOrWhiteSpace($PostRunSupervisorTrustRootPath) -or
            [string]::IsNullOrWhiteSpace($ExpectedPostRunSupervisorTrustRootSha256) -or
            [string]::IsNullOrWhiteSpace($ReleaseBundleRoot) -or
            -not [string]::IsNullOrWhiteSpace($VulcanSupervisorTrustRootPath) -or
            -not [string]::IsNullOrWhiteSpace($ExpectedVulcanSupervisorTrustRootSha256)) {
        throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_TWO_TRUST_ROOTS_AND_RELEASE_BUNDLE_REQUIRED'
    }
} elseif ($Gate -ceq 'Vulcan') {
    if (-not [string]::IsNullOrWhiteSpace($VisibleGuiTrustRootPath) -or
            -not [string]::IsNullOrWhiteSpace($ExpectedVisibleGuiTrustRootSha256) -or
            -not [string]::IsNullOrWhiteSpace($PostRunSupervisorTrustRootPath) -or
            -not [string]::IsNullOrWhiteSpace($ExpectedPostRunSupervisorTrustRootSha256)) {
        throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_TRUST_ROOTS_FEDERATION_ONLY'
    }
    if ([string]::IsNullOrWhiteSpace($ReleaseBundleRoot)) {
        throw 'MCACE_NATIVE_EVIDENCE_VULCAN_RELEASE_BUNDLE_REQUIRED'
    }
} elseif ($Gate -ceq 'ProductionAuthority') {
    if (-not [string]::IsNullOrWhiteSpace($VisibleGuiTrustRootPath) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedVisibleGuiTrustRootSha256) -or
        -not [string]::IsNullOrWhiteSpace($PostRunSupervisorTrustRootPath) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedPostRunSupervisorTrustRootSha256) -or
        -not [string]::IsNullOrWhiteSpace($VulcanSupervisorTrustRootPath) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedVulcanSupervisorTrustRootSha256)) {
        throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_TRUST_ROOTS_FEDERATION_ONLY'
    }
    if ([string]::IsNullOrWhiteSpace($ReleaseBundleRoot)) {
        throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_RELEASE_BUNDLE_REQUIRED'
    }
}

$needsCommit = $Gate -in @('Federation', 'Vulcan', 'ProductionAuthority')
if ($needsCommit -and [string]::IsNullOrWhiteSpace($CommitPath)) {
    throw "MCACE_NATIVE_EVIDENCE_COMMIT_PATH_REQUIRED|$Gate"
}
if (-not $needsCommit -and -not [string]::IsNullOrWhiteSpace($CommitPath)) {
    throw "MCACE_NATIVE_EVIDENCE_COMMIT_PATH_UNEXPECTED|$Gate"
}

$reportDoc = if ($Gate -ceq 'ProductionAuthority') {
    Read-AuthorityLockedJson $ReportPath 'report'
} else { Read-NativeJson $ReportPath 'report' }
$bindingDoc = if ($Gate -ceq 'ProductionAuthority') {
    Read-AuthorityLockedJson $BindingPath 'binding'
} else { Read-NativeJson $BindingPath 'binding' }
$commitDoc = $null
if ($needsCommit) {
    $commitDoc = if ($Gate -ceq 'ProductionAuthority') {
        Read-AuthorityLockedJson $CommitPath 'commit'
    } else { Read-NativeJson $CommitPath 'commit' }
}

$report = $reportDoc.value
$binding = $bindingDoc.value
$commit = if ($null -ne $commitDoc) { $commitDoc.value } else { $null }
$federationAttestationDoc = $null
$federationSigningRequestDoc = $null
$federationScreenshotDoc = $null
$federationRuntimeLedgerDoc = $null
$federationPostRunReceiptDoc = $null
$visibleGuiTrustRootDoc = $null
$postRunSupervisorTrustRootDoc = $null
$federationValidator = $null
$releaseBundleBinding = $null
$authorityValidator = $null
$authorityPackageDocuments = [ordered]@{}
$authorityPackagedArtifacts = [ordered]@{}
$authorityReceiptPayload = $null
$authorityReceiptChallengeSha256 = $null
$vulcanSupervisorTrustRootDoc = $null
$vulcanValidator = $null
$vulcanValidated = $null
$vulcanPackageDocuments = [ordered]@{}
if ($Gate -ceq 'Federation') {
    $nativeDirectory = [IO.Path]::GetDirectoryName([string]$commitDoc.absolute)
    $expectedInputNames = @('binding.json','commit.json','report.json','runtime-events.jsonl',
        'visible-gui-attestation.json','visible-gui-signing-request.json','visible-gui.png',
        'post-run-receipt.json')
    $entries = @(Get-ChildItem -LiteralPath $nativeDirectory -Force -ErrorAction Stop)
    if ($entries.Count -ne $expectedInputNames.Count -or
            ((@($entries.Name | Sort-Object) -join '|') -cne (($expectedInputNames | Sort-Object) -join '|'))) {
        throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_INPUT_FILE_SET_INVALID'
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or
                ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($entry.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $entry.LinkType)) {
            throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_INPUT_REPARSE_REJECTED'
        }
    }
    $expectedReportPath = [IO.Path]::GetFullPath((Join-Path $nativeDirectory 'report.json'))
    $expectedBindingPath = [IO.Path]::GetFullPath((Join-Path $nativeDirectory 'binding.json'))
    $expectedCommitPath = [IO.Path]::GetFullPath((Join-Path $nativeDirectory 'commit.json'))
    if (-not [string]::Equals($reportDoc.absolute, $expectedReportPath, [StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals($bindingDoc.absolute, $expectedBindingPath, [StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals($commitDoc.absolute, $expectedCommitPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_INPUT_CANONICAL_PATHS_REQUIRED'
    }
    $federationAttestationDoc = Read-NativeJson `
        (Join-Path $nativeDirectory 'visible-gui-attestation.json') 'visible-gui-attestation'
    $federationSigningRequestDoc = Read-NativeJson `
        (Join-Path $nativeDirectory 'visible-gui-signing-request.json') 'visible-gui-signing-request'
    $federationScreenshotDoc = Read-NativeBinary `
        (Join-Path $nativeDirectory 'visible-gui.png') 'visible-gui-screenshot'
    $federationRuntimeLedgerDoc = Read-NativeBinary `
        (Join-Path $nativeDirectory 'runtime-events.jsonl') 'federation-runtime-ledger'
    $federationPostRunReceiptDoc = Read-NativeJson `
        (Join-Path $nativeDirectory 'post-run-receipt.json') 'federation-postrun-receipt'
    $trustRootAbsolute = ConvertTo-InputAbsolutePath $VisibleGuiTrustRootPath
    $postRunTrustRootAbsolute = ConvertTo-InputAbsolutePath $PostRunSupervisorTrustRootPath
    $repoPrefix = [IO.Path]::GetFullPath($repoRoot).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    if ($trustRootAbsolute.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_TRUST_ROOT_MUST_BE_OUT_OF_BAND'
    }
    if ($postRunTrustRootAbsolute.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_POSTRUN_TRUST_ROOT_MUST_BE_OUT_OF_BAND'
    }
    if ([string]::Equals($trustRootAbsolute, $postRunTrustRootAbsolute,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_TRUST_ROOT_PATHS_MUST_DIFFER'
    }
    $visibleGuiTrustRootDoc = Read-NativeJson $trustRootAbsolute 'visible-gui-trust-root'
    $postRunSupervisorTrustRootDoc = Read-NativeJson `
        $postRunTrustRootAbsolute 'postrun-supervisor-trust-root'
    $federationValidator = New-FederationV5ValidatorModule
} elseif ($Gate -ceq 'Vulcan') {
    $nativeDirectory = [IO.Path]::GetDirectoryName([string]$commitDoc.absolute)
    $isV3Input = [string]$report.schema -ceq 'MCACE_VULCAN_GENUINE_EVENT_REPORT_V3'
    $expectedInputNames = if ($isV3Input) {
        @('binding.json','callback-provenance.jsonl','commit.json','raw-risk-event.json',
            'report.json','signing-request.json','supervisor-receipt.json')
    } else { @('binding.json','commit.json','report.json') }
    $entries = @(Get-ChildItem -LiteralPath $nativeDirectory -Force -ErrorAction Stop)
    if ($entries.Count -ne $expectedInputNames.Count -or
            ((@($entries.Name | Sort-Object) -join '|') -cne
                (($expectedInputNames | Sort-Object) -join '|'))) {
        throw 'MCACE_NATIVE_EVIDENCE_VULCAN_INPUT_FILE_SET_INVALID'
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or
                ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($entry.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $entry.LinkType)) {
            throw 'MCACE_NATIVE_EVIDENCE_VULCAN_INPUT_REPARSE_REJECTED'
        }
    }
    foreach ($actualAndLeaf in @(
            @($reportDoc.absolute,'report.json'),
            @($bindingDoc.absolute,'binding.json'),
            @($commitDoc.absolute,'commit.json'))) {
        $expected = [IO.Path]::GetFullPath((Join-Path $nativeDirectory $actualAndLeaf[1]))
        if (-not [string]::Equals([string]$actualAndLeaf[0], $expected,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'MCACE_NATIVE_EVIDENCE_VULCAN_INPUT_CANONICAL_PATHS_REQUIRED'
        }
    }
    $releaseBundleBinding = Get-NativeReleaseBundleBinding $ReleaseBundleRoot $SourceCommit
    if ($isV3Input) {
        if ([string]::IsNullOrWhiteSpace($VulcanSupervisorTrustRootPath) -or
                -not (Test-Sha256 $ExpectedVulcanSupervisorTrustRootSha256)) {
            throw 'MCACE_NATIVE_EVIDENCE_VULCAN_V3_TRUST_ROOT_REQUIRED'
        }
        $trustRootAbsolute = ConvertTo-InputAbsolutePath $VulcanSupervisorTrustRootPath
        $repoPrefix = [IO.Path]::GetFullPath($repoRoot).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
        if ($trustRootAbsolute.StartsWith($repoPrefix,[StringComparison]::OrdinalIgnoreCase)) {
            throw 'MCACE_NATIVE_EVIDENCE_VULCAN_TRUST_ROOT_MUST_BE_OUT_OF_BAND'
        }
        $vulcanSupervisorTrustRootDoc = Read-NativeJson `
            $trustRootAbsolute 'vulcan-supervisor-trust-root'
        $approvedVulcanPin = [Environment]::GetEnvironmentVariable(
            'MCACE_VULCAN_SUPERVISOR_TRUST_ROOT_SHA256','Process')
        if ([string]::IsNullOrWhiteSpace($approvedVulcanPin) -or
                $approvedVulcanPin -cnotmatch '^[0-9a-fA-F]{64}$' -or
                $approvedVulcanPin.ToLowerInvariant() -cne
                    $ExpectedVulcanSupervisorTrustRootSha256.ToLowerInvariant()) {
            throw 'MCACE_NATIVE_EVIDENCE_VULCAN_APPROVED_TRUST_ROOT_PIN_REQUIRED'
        }
        $vulcanValidator = New-VulcanV3ValidatorModule
        $bundlePaper = $releaseBundleBinding.artifacts.'mcace-server-paper.jar'
        $vulcanValidated = & $vulcanValidator {
            param($Directory,$Trust,$Pin,$Approved,$Commit,$Vulcan,$Paper,$MCAce)
            Assert-VulcanV3Package $Directory $Trust $Pin $Approved $Commit `
                $Vulcan $Paper $MCAce -RequireCurrentlyValidReceipt
        } $nativeDirectory $vulcanSupervisorTrustRootDoc `
            $ExpectedVulcanSupervisorTrustRootSha256 $approvedVulcanPin $SourceCommit `
            $reviewedVulcanSha256 ([string]$report.paper_sha256) ([string]$bundlePaper.sha256)
    }
} elseif ($Gate -ceq 'ProductionAuthority') {
    $nativeDirectory = [IO.Path]::GetDirectoryName([string]$commitDoc.absolute)
    foreach ($actualAndLeaf in @(
            @($reportDoc.absolute,'report.json'),
            @($bindingDoc.absolute,'binding.json'),
            @($commitDoc.absolute,'commit.json'))) {
        $expected = [IO.Path]::GetFullPath((Join-Path $nativeDirectory $actualAndLeaf[1]))
        if (-not [string]::Equals([string]$actualAndLeaf[0],$expected,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_INPUT_CANONICAL_PATHS_REQUIRED'
        }
    }
    $authorityValidator = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot `
        'production-authority-process-evidence.ps1'))
    Assert-PathChainNoReparse $authorityValidator $true
    if (-not (Test-Path -LiteralPath $authorityValidator -PathType Leaf)) {
        throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_VALIDATOR_REQUIRED'
    }
    $validationOutput = @(& $authorityValidator -ValidatePackageRoot $nativeDirectory `
        -ReleaseBundleRoot $ReleaseBundleRoot -RequireCurrentlyValidReceipt)
    if (($validationOutput -join "`n") -cnotlike
            '*PRODUCTION_AUTHORITY_V4_PACKAGE_VALIDATION_PASS*') {
        throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_RAW_REVALIDATION_MARKER_MISSING'
    }
    $authorityRootNames = @(
        'artifact-manifest.json','binding.json','capture-supervisor-public-descriptor.json',
        'commit.json','freeze-manifest.json','issuance-journal.log','paper-events.jsonl',
        'process-ledger.json','provider-events.jsonl','proxy-events.jsonl',
        'raw-capture-manifest.json','raw-frames.jsonl','report.json','supervisor-receipt.json')
    foreach ($leaf in $authorityRootNames) {
        $authorityPackageDocuments[$leaf] = Read-AuthorityLockedOpaqueFile `
            (Join-Path $nativeDirectory $leaf) "authority-package-$leaf"
    }
    # Replace the initially parsed triplet with the exact locked snapshots that
    # will be copied and indexed.  Cross-file races are detected again by the
    # validator over the private staging directory before publication.
    $reportDoc = Read-AuthorityLockedJson (Join-Path $nativeDirectory 'report.json') 'report-final'
    $bindingDoc = Read-AuthorityLockedJson (Join-Path $nativeDirectory 'binding.json') 'binding-final'
    $commitDoc = Read-AuthorityLockedJson (Join-Path $nativeDirectory 'commit.json') 'commit-final'
    $authorityPackageDocuments['report.json'] = $reportDoc
    $authorityPackageDocuments['binding.json'] = $bindingDoc
    $authorityPackageDocuments['commit.json'] = $commitDoc
    $report = $reportDoc.value; $binding = $bindingDoc.value; $commit = $commitDoc.value

    $artifactDirectory = Join-Path $nativeDirectory 'artifacts'
    Assert-PathChainNoReparse $artifactDirectory $true
    $artifactEntries = @(Get-ChildItem -LiteralPath $artifactDirectory -Force -ErrorAction Stop)
    if ($artifactEntries.Count -ne 10) {
        throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_ARTIFACT_SET_INVALID'
    }
    foreach ($artifactEntry in $artifactEntries) {
        if ($artifactEntry.PSIsContainer -or
                ($artifactEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                [string]$artifactEntry.Name -cnotmatch '^[A-Za-z0-9._-]+\.(?:jar|bin)$') {
            throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_ARTIFACT_ENTRY_INVALID'
        }
        $authorityPackagedArtifacts[[string]$artifactEntry.Name] =
            Read-AuthorityLockedOpaqueFile $artifactEntry.FullName `
                "authority-artifact-$($artifactEntry.Name)" $maximumAuthorityArtifactBytes
    }
    $releaseBundleBinding = Get-NativeReleaseBundleBinding $ReleaseBundleRoot $SourceCommit

    $receiptOuter = Read-AuthorityLockedJson (Join-Path $nativeDirectory 'supervisor-receipt.json') `
        'authority-supervisor-receipt'
    try { [byte[]]$receiptPayloadBytes = [Convert]::FromBase64String(
            [string](Get-RequiredProperty $receiptOuter.value 'signed_payload_base64' 'authority-receipt')) }
    catch { throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_RECEIPT_PAYLOAD_BASE64_INVALID' }
    if ((Get-BytesSha256 $receiptPayloadBytes) -cne
            [string](Get-RequiredProperty $receiptOuter.value 'signed_payload_sha256' 'authority-receipt')) {
        throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_RECEIPT_PAYLOAD_HASH_MISMATCH'
    }
    $receiptPayloadRaw = $utf8Strict.GetString($receiptPayloadBytes)
    $authorityReceiptPayload = ConvertFrom-StrictJsonRaw $receiptPayloadRaw
    try { [byte[]]$receiptChallenge = [Convert]::FromBase64String(
            [string](Get-RequiredProperty $authorityReceiptPayload 'challenge_nonce_base64' `
                'authority-receipt-payload')) }
    catch { throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_RECEIPT_CHALLENGE_INVALID' }
    if ($receiptChallenge.Length -ne 32) {
        throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_RECEIPT_CHALLENGE_INVALID'
    }
    $authorityReceiptChallengeSha256 = Get-BytesSha256 $receiptChallenge
}
$generatedAt = Get-RequiredProperty $report 'generated_at' 'report'
$generatedTime = Assert-EvidenceTime $generatedAt 'report'

$prefix = ''
$directoryName = ''
$index = $null

switch ($Gate) {
    'Federation' {
        $prefix = 'federation-gui-handoff'
        $directoryName = 'federation-gui-handoff'
        if ([string](Get-RequiredProperty $report 'schema' 'report') -cne
                'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V5') {
            throw 'FABRIC_FEDERATION_GUI_REPORT_SCHEMA_INVALID'
        }
        if ([string](Get-RequiredProperty $binding 'schema' 'binding') -cne
                'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V5') {
            throw 'FABRIC_FEDERATION_GUI_BINDING_SCHEMA_INVALID'
        }
        if ([string](Get-RequiredProperty $commit 'schema' 'commit') -cne
                'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V5') {
            throw 'FABRIC_FEDERATION_GUI_COMMIT_SCHEMA_INVALID'
        }
        $target = [string](Get-RequiredProperty $report 'fabric_target' 'report')
        if ($target -notin @('1.21.11','26.1.2','26.2')) {
            throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_TARGET_INVALID'
        }
        $sourceProxy = [string](Get-RequiredProperty $report 'source_proxy' 'report')
        $targetProxy = [string](Get-RequiredProperty $report 'target_proxy' 'report')
        if ($sourceProxy -notin @('VELOCITY','BUNGEE') -or
                $targetProxy -notin @('VELOCITY','BUNGEE')) {
            throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_TOPOLOGY_INVALID'
        }
        $bindingMetadataNames = @(
            'schema','report_schema','report_generated_at','report_sha256','source_mode',
            'source_proxy','target_proxy','visible_gui_trust_root_sha256',
            'visible_gui_attestation_sha256','visible_gui_attestation_size_bytes',
            'visible_gui_screenshot_sha256','visible_gui_screenshot_size_bytes',
            'visible_gui_screenshot_width','visible_gui_screenshot_height',
            'visible_gui_screenshot_decoded_pixel_sha256','runtime_ledger_sha256',
            'runtime_ledger_size_bytes','runtime_ledger_event_count','runtime_ledger_head_sha256',
            'runtime_ledger_supervisor_seal_sha256','release_bundle_manifest_sha256',
            'release_bundle_fabric_jar_sha256','passed')
        $current = [ordered]@{}
        foreach ($property in @($binding.PSObject.Properties)) {
            if ($property.Name -cnotin $bindingMetadataNames) {
                $current[$property.Name] = $property.Value
            }
        }
        if (-not $current.Contains('source_commit') -or
                [string]$current.source_commit -cne $SourceCommit) {
            throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_SOURCE_COMMIT_MISMATCH'
        }
        $pin = $ExpectedVisibleGuiTrustRootSha256.ToLowerInvariant()
        $postRunPin = $ExpectedPostRunSupervisorTrustRootSha256.ToLowerInvariant()
        $approvedPin = & $federationValidator {
            Get-ApprovedReleaseSignerPin `
                'MCACE_RELEASE_APPROVED_FEDERATION_GUI_TRUST_ROOT_SHA256' 'GUI'
        }
        $approvedPostRunPin = & $federationValidator {
            Get-ApprovedReleaseSignerPin `
                'MCACE_RELEASE_APPROVED_FEDERATION_POSTRUN_TRUST_ROOT_SHA256' 'POSTRUN'
        }
        if ($pin -cne $approvedPin -or $postRunPin -cne $approvedPostRunPin) {
            throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_SIGNER_PIN_NOT_APPROVED'
        }
        if ($pin -ceq $postRunPin) {
            throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_SIGNER_PINS_MUST_DIFFER'
        }
        & $federationValidator {
            param($Target,$Pin,$PostRunPin)
            $script:FabricTarget = $Target
            $script:ExpectedVisibleGuiTrustRootSha256 = $Pin
            $script:ExpectedPostRunSupervisorTrustRootSha256 = $PostRunPin
            $script:MaximumReportAgeMinutes = 5256000
            $script:fabricDescriptor = $script:fabricTargets[$Target]
            if ($null -eq $script:fabricDescriptor) {
                throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_TARGET_DESCRIPTOR_MISSING'
            }
            $script:fabricRuntimeMode = if ([int]$script:fabricDescriptor.java_major -eq 21) {
                'PRODUCTION_FINAL_REMAP_RELEASE_JAR'
            } else { 'LOOM_FINAL_NAMED_RELEASE_JAR' }
        } $target $pin $postRunPin
        $validatedSignerRoots = & $federationValidator {
            param($GuiRoot,$GuiPin,$ApprovedGuiPin,$PostRoot,$PostPin,$ApprovedPostPin)
            $gui = Assert-VisibleGuiTrustRoot $GuiRoot $GuiPin $ApprovedGuiPin
            $post = Assert-PostRunSupervisorTrustRoot $PostRoot $PostPin $ApprovedPostPin
            Assert-DistinctFederationSignerRoots $gui $post
            [pscustomobject]@{ gui=$gui; post=$post }
        } $visibleGuiTrustRootDoc $pin $approvedPin $postRunSupervisorTrustRootDoc `
            $postRunPin $approvedPostRunPin
        $validatedReport = & $federationValidator {
            param($Raw,$Current,$Source,$TargetProxy)
            Assert-PassingReportRaw $Raw $Current $Source $TargetProxy
        } $reportDoc.raw $current $sourceProxy $targetProxy
        $validatedBinding = & $federationValidator {
            param($Raw,$ReportSha,$Report,$Current)
            Assert-BindingRaw $Raw $ReportSha $Report $Current
        } $bindingDoc.raw $reportDoc.sha256 $validatedReport $current
        $releaseBundleBinding = & $federationValidator {
            param($Root,$BundleCommit,$ArtifactCommit,$Target,$SourceProxy,$TargetProxy)
            Get-ReleaseBundleTargetBinding $Root $BundleCommit $ArtifactCommit $Target $SourceProxy $TargetProxy
        } ([IO.Path]::GetFullPath($ReleaseBundleRoot)) $SourceCommit $SourceCommit `
            $target $sourceProxy $targetProxy
        if ([string]$releaseBundleBinding.bundle_source_commit -cne $SourceCommit -or
                [string]$releaseBundleBinding.artifact_source_commit -cne $SourceCommit -or
                [string]$validatedReport.source_commit -cne $SourceCommit -or
                [string]$current.fabric_artifact_sha256 -cne
                    [string]$releaseBundleBinding.fabric_jar_sha256 -or
                [string]$validatedReport.fabric_codesource_sha256_observed -cne
                    [string]$releaseBundleBinding.fabric_jar_sha256 -or
                [string]$validatedReport.release_bundle_fabric_jar_sha256 -cne
                    [string]$releaseBundleBinding.fabric_jar_sha256 -or
                [string]$validatedReport.release_bundle_fabric_jar_file -cne
                    [string]$releaseBundleBinding.fabric_jar_file -or
                [long]$validatedReport.release_bundle_fabric_jar_size_bytes -ne
                    [long]$releaseBundleBinding.fabric_jar_size_bytes) {
            throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_PROTECTED_FINAL_JAR_BINDING_INVALID'
        }

        $promptAt = Assert-EvidenceTime $validatedReport.gui_prompt_rendered_at 'gui-prompt-rendered'
        $acceptedAt = Assert-EvidenceTime $validatedReport.enablement_consent_accepted_at 'gui-accepted'
        $challengeIssuedAt = Assert-EvidenceTime $validatedReport.gui_challenge_issued_at 'gui-challenge-issued'
        $requestPreview = $federationSigningRequestDoc.value
        $requestExpected = [ordered]@{}
        foreach ($name in @($requestPreview.PSObject.Properties.Name)) {
            $requestExpected[$name] = $requestPreview.$name
        }
        $validatedSigningRequest = & $federationValidator {
            param($Evidence,$Screenshot,$Expected,$Accepted)
            Assert-VisibleGuiSigningRequest $Evidence $Screenshot $Expected $Accepted
        } $federationSigningRequestDoc $federationScreenshotDoc $requestExpected $acceptedAt
        if ([string]$federationSigningRequestDoc.sha256 -cne
                    [string]$validatedReport.operator_visible_gui_signing_request_sha256 -or
                [long]$federationSigningRequestDoc.size -ne
                    [long]$validatedReport.operator_visible_gui_signing_request_size_bytes -or
                [string]$requestPreview.schema -cne
                    [string]$validatedReport.operator_visible_gui_signing_request_schema -or
                [string]$requestPreview.domain -cne
                    [string]$validatedReport.operator_visible_gui_signing_request_domain -or
                [string]$requestPreview.source_commit -cne $SourceCommit -or
                [string]$requestPreview.artifact_source_commit -cne
                    [string]$releaseBundleBinding.artifact_source_commit -or
                [string]$requestPreview.product_version -cne
                    [string]$releaseBundleBinding.product_version -or
                [string]$requestPreview.fabric_target -cne $target -or
                [string]$requestPreview.source_proxy -cne $sourceProxy -or
                [string]$requestPreview.target_proxy -cne $targetProxy -or
                [string]$requestPreview.release_bundle_manifest_sha256 -cne
                    [string]$releaseBundleBinding.manifest_sha256 -or
                [string]$requestPreview.final_fabric_jar_sha256 -cne
                    [string]$releaseBundleBinding.fabric_jar_sha256 -or
                [string]$requestPreview.run_attempt_id -cne
                    [string]$validatedReport.run_attempt_id -or
                [string]$requestPreview.gui_attempt_id -cne
                    [string]$validatedReport.gui_attempt_id -or
                [string]$requestPreview.challenge_nonce -cne
                    [string]$validatedReport.gui_challenge_nonce -or
                [string]$requestPreview.request_created_at -cne
                    [string]$validatedReport.gui_signing_request_created_at -or
                [string]$requestPreview.expires_at -cne
                    [string]$validatedReport.gui_signing_request_expires_at -or
                [string]$requestPreview.signing_request_path_sha256 -cne
                    [string]$validatedReport.operator_visible_gui_signing_request_path_sha256 -or
                [string]$requestPreview.screenshot_path_sha256 -cne
                    [string]$validatedReport.operator_visible_gui_screenshot_path_sha256 -or
                [string]$requestPreview.attestation_output_path_sha256 -cne
                    [string]$validatedReport.operator_visible_gui_attestation_output_path_sha256) {
            throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_SIGNING_REQUEST_REPORT_BINDING_INVALID'
        }
        $validatedAttestation = & $federationValidator {
            param($Evidence,$Screenshot,$RequestEvidence,$Request,$Trust,$Pin,$Prompt,$Accepted,
                $Commit,$Target,$Jar,$Attempt,$GuiAttempt,$Challenge,$Issued,$ProcessId,$Started,
                $ApprovedPin)
            Assert-VisibleGuiAttestation $Evidence $Screenshot $RequestEvidence $Request `
                $Trust $Pin $Prompt $Accepted $Commit $Target $Jar $Attempt $GuiAttempt `
                $Challenge $Issued $ProcessId $Started $ApprovedPin
        } $federationAttestationDoc $federationScreenshotDoc $federationSigningRequestDoc `
            $validatedSigningRequest $visibleGuiTrustRootDoc $pin `
            $promptAt $acceptedAt $SourceCommit $target `
            ([string]$releaseBundleBinding.fabric_jar_sha256) `
            ([string]$validatedReport.run_attempt_id) `
            ([string]$validatedReport.gui_attempt_id) `
            ([string]$validatedReport.gui_challenge_nonce) $challengeIssuedAt `
            ([int]$validatedReport.operator_visible_gui_client_process_id) `
            ([string]$validatedReport.operator_visible_gui_client_process_started_at) $approvedPin
        $validatedLedger = & $federationValidator {
            param($Bytes,$Commit,$Target,$Attempt,$Challenge)
            Assert-RuntimeLedgerBytes $Bytes $Commit $Target $Attempt $Challenge
        } $federationRuntimeLedgerDoc.bytes $SourceCommit $target `
            ([string]$validatedReport.run_attempt_id) `
            ([string]$validatedReport.gui_challenge_nonce)

        if ([string]$federationAttestationDoc.sha256 -cne
                [string]$validatedReport.operator_visible_gui_attestation_json_sha256 -or
                [long]$federationAttestationDoc.size -ne
                    [long]$validatedReport.operator_visible_gui_attestation_json_size_bytes -or
                [string]$federationScreenshotDoc.sha256 -cne
                    [string]$validatedReport.operator_visible_gui_screenshot_sha256 -or
                [long]$federationScreenshotDoc.size -ne
                    [long]$validatedReport.operator_visible_gui_screenshot_size_bytes -or
                [string]$validatedAttestation.screenshot_decoded_pixel_sha256 -cne
                    [string]$validatedReport.operator_visible_gui_screenshot_decoded_pixel_sha256 -or
                [string]$federationRuntimeLedgerDoc.sha256 -cne
                    [string]$validatedReport.runtime_ledger_sha256 -or
                [long]$federationRuntimeLedgerDoc.size -ne
                    [long]$validatedReport.runtime_ledger_size_bytes -or
                [int]$validatedLedger.event_count -ne [int]$validatedReport.runtime_ledger_event_count -or
                [string]$validatedLedger.head_sha256 -cne
                    [string]$validatedReport.runtime_ledger_head_sha256 -or
                [string]$validatedLedger.supervisor_seal_sha256 -cne
                    [string]$validatedReport.runtime_ledger_supervisor_seal_sha256 -or
                [string]$validatedLedger.gui_receipt_attestation_sha256 -cne
                    [string]$federationAttestationDoc.sha256) {
            throw 'MCACE_NATIVE_EVIDENCE_FEDERATION_SIGNED_GUI_LEDGER_HASH_CHAIN_INVALID'
        }
        foreach ($correlation in @(
                @('source_negative_attempt_id','source_negative_attempt_id'),
                @('source_negative_peer','source_negative_peer'),
                @('source_negative_connection_id','source_negative_connection_id'),
                @('source_negative_session_id','source_negative_session_id'),
                @('source_negative_subject_commitment_sha256','source_negative_subject_commitment_sha256'),
                @('target_negative_attempt_id','target_negative_attempt_id'),
                @('target_negative_peer','target_negative_peer'),
                @('target_negative_connection_id','target_negative_connection_id'),
                @('target_negative_session_id','target_negative_session_id'),
                @('target_negative_subject_commitment_sha256','target_negative_subject_commitment_sha256'))) {
            if ([string]$validatedLedger.($correlation[0]) -cne
                    [string]$validatedReport.($correlation[1])) {
                throw "MCACE_NATIVE_EVIDENCE_FEDERATION_RUNTIME_CORRELATION_INVALID|$($correlation[0])"
            }
        }
        $postRunChallengeIssuedAt = Assert-EvidenceTime `
            $federationPostRunReceiptDoc.value.postrun_challenge_issued_at `
            'federation-postrun-challenge-issued'
        $normalizedReportEvidence = [pscustomobject]@{
            sha256=[string]$reportDoc.sha256; size_bytes=[long]$reportDoc.size
        }
        $normalizedBindingEvidence = [pscustomobject]@{
            sha256=[string]$bindingDoc.sha256; size_bytes=[long]$bindingDoc.size
        }
        $normalizedAttestationEvidence = [pscustomobject]@{
            sha256=[string]$federationAttestationDoc.sha256
            size_bytes=[long]$federationAttestationDoc.size
        }
        $normalizedScreenshotEvidence = [pscustomobject]@{
            sha256=[string]$federationScreenshotDoc.sha256
            size_bytes=[long]$federationScreenshotDoc.size
        }
        $normalizedLedgerEvidence = [pscustomobject]@{
            sha256=[string]$federationRuntimeLedgerDoc.sha256
            size_bytes=[long]$federationRuntimeLedgerDoc.size
        }
        $postRunExpected = & $federationValidator {
            param($Release,$Report,$ReportEvidence,$BindingEvidence,$AttestationEvidence,
                $ScreenshotEvidence,$Attestation,$LedgerEvidence,$Ledger,$Operation,$Challenge,
                $Issued)
            Get-PostRunReceiptExpectedBinding $Release $Report $ReportEvidence $BindingEvidence `
                $AttestationEvidence $ScreenshotEvidence $Attestation $LedgerEvidence $Ledger `
                $Operation $Challenge $Issued
        } $releaseBundleBinding $validatedReport $normalizedReportEvidence `
            $normalizedBindingEvidence $normalizedAttestationEvidence $normalizedScreenshotEvidence `
            $validatedAttestation $normalizedLedgerEvidence $validatedLedger `
            ([string]$federationPostRunReceiptDoc.value.postrun_operation_attempt_id) `
            ([string]$federationPostRunReceiptDoc.value.postrun_challenge_nonce) `
            ([string]$federationPostRunReceiptDoc.value.postrun_challenge_issued_at)
        $validatedPostRunReceipt = & $federationValidator {
            param($Evidence,$Trust,$Pin,$ApprovedPin,$Expected,$Issued)
            Assert-PostRunReceipt $Evidence $Trust $Pin $ApprovedPin $Expected $Issued
        } $federationPostRunReceiptDoc $postRunSupervisorTrustRootDoc $postRunPin `
            $approvedPostRunPin $postRunExpected $postRunChallengeIssuedAt
        $normalizedPostRunReceiptEvidence = [pscustomobject]@{
            sha256=[string]$federationPostRunReceiptDoc.sha256
            size_bytes=[long]$federationPostRunReceiptDoc.size
        }
        $null = & $federationValidator {
            param($Raw,$ReportSha,$BindingSha,$Report,$ReceiptEvidence,$Receipt)
            Assert-CommitRaw $Raw $ReportSha $BindingSha $Report $ReceiptEvidence $Receipt
        } $commitDoc.raw $reportDoc.sha256 $bindingDoc.sha256 $validatedReport `
            $normalizedPostRunReceiptEvidence $validatedPostRunReceipt.value
        Assert-ReportHashBinding $binding $reportDoc
        Assert-CommitHashBinding $commit $reportDoc $bindingDoc
        Assert-SameEvidenceTime $binding.report_generated_at $generatedAt 'binding-report'
        if ([string]::IsNullOrWhiteSpace($EvidenceId)) {
            $route = "$($sourceProxy.ToLowerInvariant())-to-$($targetProxy.ToLowerInvariant())"
            $EvidenceId = "$prefix-$(Get-SafeTimeToken $generatedTime)-$target-$route-$($SourceCommit.Substring(0,7))"
        }
        Assert-SafeEvidenceId $EvidenceId $prefix
        $nativePrefix = "$evidenceRootRelative/$directoryName/$EvidenceId"
        $index = [pscustomobject][ordered]@{
            schema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V5'
            generated_at = [string]$generatedAt
            source_commit = $SourceCommit
            artifact_source_commit = [string]$releaseBundleBinding.artifact_source_commit
            release_bundle_source_commit = [string]$releaseBundleBinding.bundle_source_commit
            fabric_target = $target
            source_proxy = $sourceProxy
            target_proxy = $targetProxy
            gui_attempt_id = [string]$validatedReport.gui_attempt_id
            gui_challenge_nonce = [string]$validatedReport.gui_challenge_nonce
            postrun_operation_attempt_id = [string]$validatedPostRunReceipt.value.postrun_operation_attempt_id
            postrun_challenge_nonce = [string]$validatedPostRunReceipt.value.postrun_challenge_nonce
            visible_gui_trust_root_sha256 = $pin
            postrun_supervisor_trust_root_sha256 = $postRunPin
            postrun_signer_key_id = [string]$validatedPostRunReceipt.value.signer_key_id
            release_bundle_manifest_sha256 = [string]$releaseBundleBinding.manifest_sha256
            release_bundle_fabric_jar_file = [string]$releaseBundleBinding.fabric_jar_file
            release_bundle_fabric_jar_sha256 = [string]$releaseBundleBinding.fabric_jar_sha256
            release_bundle_paper_jar_sha256 = [string]$releaseBundleBinding.paper_jar_sha256
            release_bundle_source_proxy_jar_sha256 = [string]$releaseBundleBinding.source_proxy_jar_sha256
            release_bundle_target_proxy_jar_sha256 = [string]$releaseBundleBinding.target_proxy_jar_sha256
            canonical_evidence = [pscustomobject][ordered]@{
                report = New-Descriptor "$nativePrefix/report.json" $reportDoc
                binding = New-Descriptor "$nativePrefix/binding.json" $bindingDoc
                commit = New-Descriptor "$nativePrefix/commit.json" $commitDoc
                visible_gui_attestation = New-Descriptor `
                    "$nativePrefix/visible-gui-attestation.json" $federationAttestationDoc
                visible_gui_signing_request = New-Descriptor `
                    "$nativePrefix/visible-gui-signing-request.json" $federationSigningRequestDoc
                visible_gui_screenshot = New-Descriptor `
                    "$nativePrefix/visible-gui.png" $federationScreenshotDoc
                runtime_event_ledger = New-Descriptor `
                    "$nativePrefix/runtime-events.jsonl" $federationRuntimeLedgerDoc
                post_run_receipt = New-Descriptor `
                    "$nativePrefix/post-run-receipt.json" $federationPostRunReceiptDoc
            }
        }
    }
    'Vulcan' {
        $prefix = 'vulcan-genuine-event'
        $directoryName = 'vulcan-genuine-event'
        if ([string]$report.schema -ceq 'MCACE_VULCAN_GENUINE_EVENT_REPORT_V3') {
            if ($null -eq $vulcanValidated -or [bool]$vulcanValidated.report.fixture -or
                    [bool]$vulcanValidated.receipt.fixture) {
                throw 'MCACE_NATIVE_EVIDENCE_VULCAN_V3_FIXTURE_RELEASE_REJECTED'
            }
            $bundleMCAce = $releaseBundleBinding.artifacts.'mcace-server-paper.jar'
            if ($null -eq $bundleMCAce -or
                    [string]$releaseBundleBinding.artifact_source_commit -cne $SourceCommit -or
                    [string]$bundleMCAce.sha256 -cne [string]$report.mcace_sha256 -or
                    [long]$bundleMCAce.size_bytes -ne [long]$report.mcace_size) {
                throw 'MCACE_NATIVE_EVIDENCE_VULCAN_V3_FINAL_MCACE_PAPER_JAR_BINDING_INVALID'
            }
            $vulcanPackageDocuments['report.json']=$reportDoc
            $vulcanPackageDocuments['binding.json']=$bindingDoc
            $vulcanPackageDocuments['commit.json']=$commitDoc
            $vulcanPackageDocuments['signing-request.json']=Read-NativeJson `
                (Join-Path $nativeDirectory 'signing-request.json') 'vulcan-signing-request'
            $vulcanPackageDocuments['supervisor-receipt.json']=Read-NativeJson `
                (Join-Path $nativeDirectory 'supervisor-receipt.json') 'vulcan-supervisor-receipt'
            $vulcanPackageDocuments['raw-risk-event.json']=Read-NativeBinary `
                (Join-Path $nativeDirectory 'raw-risk-event.json') 'vulcan-raw-risk-event'
            $vulcanPackageDocuments['callback-provenance.jsonl']=Read-NativeBinary `
                (Join-Path $nativeDirectory 'callback-provenance.jsonl') 'vulcan-callback-provenance'
            if ([string]::IsNullOrWhiteSpace($EvidenceId)) {
                $EvidenceId = "$prefix-$(Get-SafeTimeToken $generatedTime)-$($SourceCommit.Substring(0,12))"
            }
            Assert-SafeEvidenceId $EvidenceId $prefix
            $nativePrefix = "$evidenceRootRelative/$directoryName/$EvidenceId"
            $canonical = [ordered]@{}
            foreach ($entry in $vulcanPackageDocuments.GetEnumerator()) {
                $role = [IO.Path]::GetFileNameWithoutExtension([string]$entry.Key).Replace('-','_')
                $canonical[$role] = New-Descriptor "$nativePrefix/$($entry.Key)" $entry.Value
            }
            $index = [pscustomobject][ordered]@{
                schema='MCACE_VULCAN_GENUINE_EVENT_EVIDENCE_INDEX_V3'
                generated_at=[string]$report.generated_at
                source_mode='PUBLISHED_EXTERNALLY_SUPERVISED_VULCAN_V3'
                source_commit=$SourceCommit
                artifact_source_commit=$SourceCommit
                product_version='0.0.1'
                release_eligible=$true
                fixture=$false
                run_attempt_id=[string]$report.run_attempt_id
                challenge_nonce=[string]$report.challenge_nonce
                supervisor_trust_root_sha256=$ExpectedVulcanSupervisorTrustRootSha256.ToLowerInvariant()
                supervisor_signer_key_id=[string]$vulcanValidated.receipt.signer_key_id
                receipt_issued_at=[string]$vulcanValidated.receipt.signed_at
                receipt_expires_at=[string]$vulcanValidated.receipt.expires_at
                vulcan_sha256=[string]$report.vulcan_sha256
                vulcan_size=[long]$report.vulcan_size
                upstream_paper_sha256=[string]$report.paper_sha256
                upstream_paper_size=[long]$report.paper_size
                mcace_server_paper_sha256=[string]$report.mcace_sha256
                mcace_server_paper_size=[long]$report.mcace_size
                callback_record_sha256=[string]$report.callback_record_sha256
                raw_event_sha256=[string]$report.raw_event_sha256
                callback_ledger_sha256=[string]$report.callback_ledger_sha256
                provider_plugin_main_class=[string]$report.provider_plugin_main_class
                provider_event_class=[string]$report.provider_event_class
                accessor_provenance_sha256=[string]$report.accessor_provenance_sha256
                release_bundle_manifest_sha256=[string]$releaseBundleBinding.manifest_sha256
                release_bundle_source_commit=[string]$releaseBundleBinding.source_commit
                release_bundle_paper_jar_sha256=[string]$bundleMCAce.sha256
                canonical_evidence=[pscustomobject]$canonical
            }
            break
        }
        $reportNames = @(
            'schema','generated_at','source_mode','source_commit','product_version',
            'release_eligible','vulcan_sha256','paper_sha256','mcace_sha256',
            'vulcan_size','paper_size','mcace_size','plugin_name','plugin_version',
            'provider','provider_version','event_type','source_component','origin',
            'network_policy','network_isolation_operator_attested',
            'network_isolation_os_verified_by_script',
            'genuine_external_trigger_operator_attested',
            'no_synthetic_event_injection_operator_attested',
            'gate_invoked_plugin_manager_call_event','gate_used_test_fixture',
            'gate_used_vendor_synthetic_event','paper_process_coverage',
            'licensed_plugin_enablement_coverage','mcace_listener_registration_coverage',
            'mcace_adapter_extraction_coverage','mcace_correlator_coverage',
            'mcace_queue_auth_delivery_coverage','real_behavior_event_delivery_coverage',
            'expected_player_matched','observer_auth_protocol',
            'observer_challenge_signature_verified','observer_challenge_exchange_count',
            'observer_access_token_run_bound','observer_event_causality_verified',
            'observer_distinct_event_count','unique_matching_event_count',
            'total_risk_event_count','check_nonempty','stable_check_nonempty','flag_count',
            'temporary_paper_remap_allowed','temporary_material_removed',
            'remaining_marker_process_count','limitations','passed')
        $bindingNames = @(
            'schema','report_schema','report_generated_at','report_sha256','report_size_bytes',
            'source_mode','source_commit','product_version','release_eligible',
            'vulcan_sha256','paper_sha256','mcace_sha256','vulcan_size','paper_size',
            'mcace_size','wrapper_sha256','source_manifest_sha256','source_file_count',
            'java_executable_sha256','java_file_version','prepared_manifest_sha256',
            'prepared_file_count','passed')
        $commitNames = @(
            'schema','generated_at','report_schema','binding_schema','report_generated_at',
            'report_sha256','report_size_bytes','binding_sha256','binding_size_bytes',
            'source_mode','source_commit','product_version','release_eligible','committed')
        if (-not (Test-ExactProperties $report $reportNames) -or
                -not (Test-ExactProperties $binding $bindingNames) -or
                -not (Test-ExactProperties $commit $commitNames)) {
            throw 'MCACE_NATIVE_EVIDENCE_VULCAN_V2_PROPERTY_SET_INVALID'
        }
        Assert-Schema $report 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_V2' 'report'
        Assert-Schema $binding 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_BINDING_V2' 'binding'
        Assert-Schema $commit 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_COMMIT_V2' 'commit'
        foreach ($docAndRole in @(
                [pscustomobject]@{ value=$report; role='report' },
                [pscustomobject]@{ value=$binding; role='binding' },
                [pscustomobject]@{ value=$commit; role='commit' })) {
            if (-not (Test-StringEqual $docAndRole.value.source_commit $SourceCommit) -or
                    -not (Test-StringEqual $docAndRole.value.product_version '0.0.1') -or
                    -not (Test-False $docAndRole.value.release_eligible)) {
                throw "MCACE_NATIVE_EVIDENCE_VULCAN_V2_DIAGNOSTIC_IDENTITY_INVALID|$($docAndRole.role)"
            }
        }
        if (-not (Test-StringEqual $report.source_mode 'EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED') -or
                -not (Test-StringEqual $binding.source_mode 'EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED') -or
                -not (Test-StringEqual $commit.source_mode 'EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED') -or
                -not (Test-True $report.passed) -or -not (Test-True $binding.passed) -or
                -not (Test-True $commit.committed)) {
            throw 'MCACE_NATIVE_EVIDENCE_VULCAN_V2_DIAGNOSTIC_STATE_INVALID'
        }
        Assert-SameEvidenceTime $binding.report_generated_at $generatedAt 'vulcan-binding-report'
        Assert-SameEvidenceTime $commit.generated_at $generatedAt 'vulcan-commit-generated'
        Assert-SameEvidenceTime $commit.report_generated_at $generatedAt 'vulcan-commit-report'
        if (-not (Test-StringEqual $binding.report_schema 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_V2') -or
                -not (Test-StringEqual $binding.report_sha256 $reportDoc.sha256) -or
                -not (Test-JsonInteger $binding.report_size_bytes) -or
                    [long]$binding.report_size_bytes -ne [long]$reportDoc.size_bytes -or
                -not (Test-StringEqual $commit.report_schema 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_V2') -or
                -not (Test-StringEqual $commit.binding_schema 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_BINDING_V2') -or
                -not (Test-StringEqual $commit.report_sha256 $reportDoc.sha256) -or
                -not (Test-JsonInteger $commit.report_size_bytes) -or
                    [long]$commit.report_size_bytes -ne [long]$reportDoc.size_bytes -or
                -not (Test-StringEqual $commit.binding_sha256 $bindingDoc.sha256) -or
                -not (Test-JsonInteger $commit.binding_size_bytes) -or
                    [long]$commit.binding_size_bytes -ne [long]$bindingDoc.size_bytes) {
            throw 'MCACE_NATIVE_EVIDENCE_VULCAN_V2_DIAGNOSTIC_CHAIN_INVALID'
        }
        foreach ($name in @('vulcan_sha256','paper_sha256','mcace_sha256')) {
            if (-not (Test-Sha256 $report.$name) -or
                    -not (Test-StringEqual $binding.$name ([string]$report.$name))) {
                throw "MCACE_NATIVE_EVIDENCE_VULCAN_PRODUCT_HASH_INVALID|$name"
            }
        }
        foreach ($name in @('vulcan_size','paper_size','mcace_size')) {
            if (-not (Test-JsonInteger $report.$name) -or [long]$report.$name -le 0 -or
                    -not (Test-JsonInteger $binding.$name) -or
                    [long]$binding.$name -ne [long]$report.$name) {
                throw "MCACE_NATIVE_EVIDENCE_VULCAN_PRODUCT_SIZE_INVALID|$name"
            }
        }
        if (-not (Test-StringEqual $report.vulcan_sha256 $reviewedVulcanSha256) -or
                [long]$report.vulcan_size -ne $reviewedVulcanSize -or
                -not (Test-StringEqual $report.observer_auth_protocol 'MCACE_VULCAN_OBSERVER_AUTH_V1') -or
                -not (Test-True $report.observer_challenge_signature_verified) -or
                -not (Test-JsonInteger $report.observer_challenge_exchange_count) -or
                    [int]$report.observer_challenge_exchange_count -ne 1 -or
                -not (Test-True $report.observer_access_token_run_bound) -or
                -not (Test-True $report.observer_event_causality_verified) -or
                -not (Test-JsonInteger $report.observer_distinct_event_count) -or
                    [int]$report.observer_distinct_event_count -ne 1 -or
                -not (Test-JsonArray $report.limitations) -or
                ((@($report.limitations) -join '|') -cne
                    'HUMAN_TRIGGER_ORIGIN_OPERATOR_ATTESTED_NOT_OS_OR_VENDOR_VERIFIED_BY_SCRIPT|NETWORK_ISOLATION_OPERATOR_ATTESTED_NOT_OS_VERIFIED_BY_SCRIPT|OBSERVER_CLIENT_IDENTITY_USES_PUBLIC_RFC8032_TEST_VECTOR_NOT_EXTERNAL_TRUST_ANCHOR|OPERATOR_ATTESTED_V2_EVIDENCE_NOT_RELEASE_ELIGIBLE_WITHOUT_EXTERNAL_PINNED_SUPERVISOR_RECEIPT')) {
            throw 'MCACE_NATIVE_EVIDENCE_VULCAN_V2_DIAGNOSTIC_SEMANTICS_INVALID'
        }
        if (-not (Test-Sha256 $binding.wrapper_sha256) -or
                -not (Test-Sha256 $binding.source_manifest_sha256) -or
                -not (Test-JsonInteger $binding.source_file_count) -or
                    [long]$binding.source_file_count -le 0 -or
                -not (Test-Sha256 $binding.java_executable_sha256) -or
                -not (Test-NonEmptyJsonString $binding.java_file_version) -or
                -not (Test-Sha256 $binding.prepared_manifest_sha256) -or
                -not (Test-JsonInteger $binding.prepared_file_count) -or
                    [long]$binding.prepared_file_count -le 0) {
            throw 'MCACE_NATIVE_EVIDENCE_VULCAN_BINDING_INVALID'
        }
        $currentWrapper = Read-NativeBinary `
            (Join-Path $repoRoot 'scripts/vulcan-genuine-event-smoke.ps1') `
            'vulcan-wrapper'
        & git -C $repoRoot diff --quiet $SourceCommit -- scripts/vulcan-genuine-event-smoke.ps1
        if ($LASTEXITCODE -ne 0 -or $currentWrapper.sha256 -cne [string]$binding.wrapper_sha256) {
            throw 'MCACE_NATIVE_EVIDENCE_VULCAN_WRAPPER_SOURCE_BINDING_INVALID'
        }
        $bundleMCAce = $releaseBundleBinding.artifacts.'mcace-server-paper.jar'
        if ($null -eq $bundleMCAce -or
                [string]$releaseBundleBinding.artifact_source_commit -cne $SourceCommit -or
                [string]$releaseBundleBinding.product_version -cne '0.0.1' -or
                [string]$bundleMCAce.sha256 -cne [string]$report.mcace_sha256 -or
                [long]$bundleMCAce.size_bytes -ne [long]$report.mcace_size) {
            throw 'MCACE_NATIVE_EVIDENCE_VULCAN_FINAL_MCACE_PAPER_JAR_BINDING_INVALID'
        }
        # V2 uses a public RFC 8032 fixture identity and local operator attestations.  Its
        # cross-hashes remain useful diagnostics, but it cannot mint release evidence.
        throw 'MCACE_NATIVE_EVIDENCE_VULCAN_V2_DIAGNOSTIC_NOT_RELEASE_GRADE'
    }
    'ProductionAuthority' {
        $prefix = 'server-confirmed-production'
        $directoryName = 'server-confirmed-production'
        Assert-Schema $report 'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_REPORT_V4' 'report'
        Assert-Schema $binding 'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_BINDING_V4' 'binding'
        Assert-Schema $commit 'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_COMMIT_V4' 'commit'
        if (-not (Test-StringEqual $report.source_mode `
                    'EXECUTED_EXTERNAL_SUPERVISOR_PRODUCTION_AUTHORITY') -or
                -not (Test-StringEqual $report.evidence_class `
                    'EXTERNAL_SUPERVISOR_SIGNED_PRODUCTION_AUTHORITY_PREPUBLICATION') -or
                -not (Test-True $report.server_confirmed_only) -or
                -not (Test-True $report.independent_supervisor_signature_verified) -or
                -not (Test-True $report.passed) -or -not (Test-True $binding.passed) -or
                -not (Test-True $commit.committed) -or
                -not (Test-False $report.release_eligible) -or
                -not (Test-False $binding.release_eligible) -or
                -not (Test-False $commit.release_eligible) -or
                -not (Test-StringEqual $report.action_ceiling 'MONITOR') -or
                [long]$report.automatic_action_count -ne 0) {
            throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_V4_PREPUBLICATION_STATE_INVALID'
        }
        foreach ($docAndRole in @(
                [pscustomobject]@{ value = $report; role = 'report' },
                [pscustomobject]@{ value = $binding; role = 'binding' },
                [pscustomobject]@{ value = $commit; role = 'commit' })) {
            if (-not (Test-StringEqual $docAndRole.value.source_commit $SourceCommit) -or
                    -not (Test-StringEqual $docAndRole.value.artifact_source_commit $SourceCommit)) {
                throw "MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_SOURCE_COMMIT_MISMATCH|$($docAndRole.role)"
            }
        }
        Assert-SameEvidenceTime $binding.generated_at $generatedAt 'authority-binding-generated'
        Assert-SameEvidenceTime $commit.generated_at $generatedAt 'authority-commit-generated'
        Assert-ReportHashBinding $binding $reportDoc
        Assert-CommitHashBinding $commit $reportDoc $bindingDoc
        foreach ($hashField in @('supervisor_descriptor_sha256','supervisor_receipt_sha256',
                'raw_evidence_root_sha256','raw_frame_set_sha256',
                'provider_evidence_commitment_sha256','profile_sha256','topology_sha256')) {
            if (-not (Test-Sha256 $report.$hashField)) {
                throw "MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_HASH_INVALID|$hashField"
            }
        }
        if (-not (Test-StringEqual $authorityReceiptPayload.operation_attempt_id `
                    $report.operation_attempt_id) -or
                -not (Test-StringEqual $authorityReceiptPayload.capture_id $report.capture_id) -or
                -not (Test-StringEqual $authorityReceiptPayload.raw_evidence_root_sha256 `
                    $report.raw_evidence_root_sha256) -or
                -not (Test-StringEqual $authorityReceiptPayload.provider_evidence_commitment_sha256 `
                    $report.provider_evidence_commitment_sha256)) {
            throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_RECEIPT_REPORT_BINDING_INVALID'
        }
        $paperBundle = $releaseBundleBinding.artifacts.'mcace-server-paper.jar'
        $velocityBundle = $releaseBundleBinding.artifacts.'mcace-server-velocity.jar'
        $bungeeBundle = $releaseBundleBinding.artifacts.'mcace-server-bungeecord.jar'
        if ([string]$releaseBundleBinding.source_commit -cne $SourceCommit -or
                [string]$releaseBundleBinding.artifact_source_commit -cne $SourceCommit -or
                [string]$paperBundle.sha256 -cne [string]$report.paper_jar_sha256 -or
                [string]$velocityBundle.sha256 -cne [string]$report.velocity_jar_sha256 -or
                [string]$bungeeBundle.sha256 -cne [string]$report.bungeecord_jar_sha256) {
            throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_RELEASE_BUNDLE_CROSS_BINDING_INVALID'
        }

        # A signed attempt/challenge is single-use for publication.  Force may
        # replace a destination but may never mint a second release record from
        # the same supervisor receipt.
        if (Test-Path -LiteralPath $evidenceRoot -PathType Container) {
            foreach ($existing in @(Get-ChildItem -LiteralPath $evidenceRoot -File -Force `
                    -Filter 'server-confirmed-production-*.json' -ErrorAction Stop)) {
                $existingDoc = Read-AuthorityLockedJson $existing.FullName 'authority-existing-index'
                if ([string]$existingDoc.value.schema -ceq
                        'MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V4' -and
                        ([string]$existingDoc.value.operation_attempt_id -ceq
                            [string]$report.operation_attempt_id -or
                         [string]$existingDoc.value.supervisor_challenge_sha256 -ceq
                            $authorityReceiptChallengeSha256)) {
                    throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_RECEIPT_REPLAY_REJECTED'
                }
            }
        }
        if ([string]::IsNullOrWhiteSpace($EvidenceId)) {
            $EvidenceId = "$prefix-$(Get-SafeTimeToken $generatedTime)-$($SourceCommit.Substring(0,7))"
        }
        Assert-SafeEvidenceId $EvidenceId $prefix
        $nativePrefix = "$evidenceRootRelative/$directoryName/$EvidenceId"

        $canonicalNames = [ordered]@{
            artifact_manifest='artifact-manifest.json'; binding='binding.json'
            capture_supervisor_public_descriptor='capture-supervisor-public-descriptor.json'
            commit='commit.json'; freeze_manifest='freeze-manifest.json'
            issuance_journal='issuance-journal.log'; paper_events='paper-events.jsonl'
            process_ledger='process-ledger.json'; provider_events='provider-events.jsonl'
            proxy_events='proxy-events.jsonl'; raw_capture_manifest='raw-capture-manifest.json'
            raw_frames='raw-frames.jsonl'; report='report.json'
            supervisor_receipt='supervisor-receipt.json'
        }
        $canonicalEvidence = [ordered]@{}
        foreach ($canonicalName in $canonicalNames.GetEnumerator()) {
            $canonicalEvidence[[string]$canonicalName.Key] = New-Descriptor `
                "$nativePrefix/$($canonicalName.Value)" `
                $authorityPackageDocuments[[string]$canonicalName.Value]
        }
        $artifactManifestRaw = $utf8Strict.GetString(
            $authorityPackageDocuments['artifact-manifest.json'].bytes)
        $artifactManifest = ConvertFrom-StrictJsonRaw $artifactManifestRaw
        $artifactRoles = @('java_runtime','minecraft_client','fabric_loader','mcace_client_fabric',
            'paper_server','mcace_server_paper','grim','vulcan','mcace_server_velocity',
            'mcace_server_bungeecord')
        $packagedArtifactEvidence = [ordered]@{}
        foreach ($artifactRole in $artifactRoles) {
            $artifactEntry = $artifactManifest.$artifactRole
            $leaf = [IO.Path]::GetFileName([string]$artifactEntry.relative_path)
            if ([string]::IsNullOrWhiteSpace($leaf) -or
                    -not $authorityPackagedArtifacts.Contains($leaf)) {
                throw "MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_ARTIFACT_ROLE_MISSING|$artifactRole"
            }
            $artifactDoc = $authorityPackagedArtifacts[$leaf]
            if ([string]$artifactEntry.sha256 -cne [string]$artifactDoc.sha256 -or
                    [long]$artifactEntry.size_bytes -ne [long]$artifactDoc.size_bytes) {
                throw "MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_ARTIFACT_ROLE_MISMATCH|$artifactRole"
            }
            $packagedArtifactEvidence[$artifactRole] = New-Descriptor `
                "$nativePrefix/artifacts/$leaf" $artifactDoc
        }
        $index = [pscustomobject][ordered]@{
            schema = 'MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V4'
            generated_at = [string]$generatedAt
            source_commit = $SourceCommit
            artifact_source_commit = $SourceCommit
            product_version = '0.0.1'
            evidence_class = 'EXTERNAL_SUPERVISOR_SIGNED_RAW_REVALIDATED_PRODUCTION_AUTHORITY'
            release_eligible = $true
            capture_id = [string]$report.capture_id
            operation_attempt_id = [string]$report.operation_attempt_id
            supervisor_challenge_sha256 = $authorityReceiptChallengeSha256
            supervisor_descriptor_sha256 = [string]$report.supervisor_descriptor_sha256
            supervisor_key_id_sha256 = [string]$report.supervisor_key_id_sha256
            supervisor_receipt_sha256 = [string]$report.supervisor_receipt_sha256
            receipt_issued_at = [string]$authorityReceiptPayload.issued_at
            receipt_expires_at = [string]$authorityReceiptPayload.expires_at
            raw_evidence_root_sha256 = [string]$report.raw_evidence_root_sha256
            raw_frame_set_sha256 = [string]$report.raw_frame_set_sha256
            provider_evidence_commitment_sha256 = [string]$report.provider_evidence_commitment_sha256
            profile_sha256 = [string]$report.profile_sha256
            topology_sha256 = [string]$report.topology_sha256
            selected_proxy = [string]$report.selected_proxy
            action_ceiling = 'MONITOR'
            release_bundle = [pscustomobject][ordered]@{
                schema='MCACE_RELEASE_BUNDLE_V4'
                manifest_sha256=[string]$releaseBundleBinding.manifest_sha256
                source_commit=[string]$releaseBundleBinding.source_commit
                artifact_source_commit=[string]$releaseBundleBinding.artifact_source_commit
                paper_jar=[pscustomobject][ordered]@{sha256=[string]$paperBundle.sha256;size_bytes=[long]$paperBundle.size_bytes}
                velocity_jar=[pscustomobject][ordered]@{sha256=[string]$velocityBundle.sha256;size_bytes=[long]$velocityBundle.size_bytes}
                bungeecord_jar=[pscustomobject][ordered]@{sha256=[string]$bungeeBundle.sha256;size_bytes=[long]$bungeeBundle.size_bytes}
            }
            canonical_evidence = [pscustomobject]$canonicalEvidence
            packaged_artifacts = [pscustomobject]$packagedArtifactEvidence
        }
    }
}

if ($null -ne $federationValidator) {
    Remove-Module $federationValidator -Force -ErrorAction SilentlyContinue
    $federationValidator = $null
}
if ($null -ne $vulcanValidator) {
    Remove-Module $vulcanValidator -Force -ErrorAction SilentlyContinue
    $vulcanValidator = $null
}

$publishMutex = Enter-NativeEvidencePublishMutex
try {
Assert-DestinationBaseSafe

if ($Gate -ceq 'Federation' -and $null -ne $index -and
        [string]$index.schema -ceq 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V5') {
    Assert-FederationNoPublicationReplay $index
}

if ($Gate -ceq 'ProductionAuthority' -and $null -ne $index -and
        [string]$index.schema -ceq 'MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V4') {
    foreach ($existing in @(Get-ChildItem -LiteralPath $evidenceRoot -File -Force `
            -Filter 'server-confirmed-production-*.json' -ErrorAction SilentlyContinue)) {
        $existingDoc = Read-AuthorityLockedJson $existing.FullName 'authority-existing-index-locked'
        if ([string]$existingDoc.value.schema -ceq
                'MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V4' -and
                ([string]$existingDoc.value.operation_attempt_id -ceq
                    [string]$index.operation_attempt_id -or
                 [string]$existingDoc.value.supervisor_challenge_sha256 -ceq
                    [string]$index.supervisor_challenge_sha256)) {
            throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_RECEIPT_REPLAY_REJECTED'
        }
    }
}

if ($Gate -ceq 'Vulcan' -and $null -ne $index -and
        [string]$index.schema -ceq 'MCACE_VULCAN_GENUINE_EVENT_EVIDENCE_INDEX_V3') {
    foreach ($existingPath in @(Get-ChildItem -LiteralPath $evidenceRoot -File -Force `
            -Filter 'vulcan-genuine-event-*.json' -ErrorAction SilentlyContinue)) {
        $existing = Read-NativeJson $existingPath.FullName 'existing-vulcan-v3-index'
        if ([string]$existing.value.schema -ceq 'MCACE_VULCAN_GENUINE_EVENT_EVIDENCE_INDEX_V3' -and
                ([string]$existing.value.run_attempt_id -ceq [string]$index.run_attempt_id -or
                 [string]$existing.value.challenge_nonce -ceq [string]$index.challenge_nonce)) {
            throw 'MCACE_NATIVE_EVIDENCE_VULCAN_V3_REPLAY_REJECTED'
        }
    }
}

$gateRoot = Join-Path $evidenceRoot $directoryName
if (-not (Test-Path -LiteralPath $gateRoot)) {
    [void][IO.Directory]::CreateDirectory($gateRoot)
}
Assert-PathChainNoReparse $gateRoot $true

$finalDirectory = Join-Path $gateRoot $EvidenceId
$finalIndex = Join-Path $evidenceRoot ($EvidenceId + '.json')
foreach ($destination in @($finalDirectory, $finalIndex)) {
    if (Test-Path -LiteralPath $destination) {
        Assert-PathChainNoReparse $destination $true
        if (-not $Force) { throw "MCACE_NATIVE_EVIDENCE_DESTINATION_EXISTS|$destination" }
    }
}

$transactionId = [Guid]::NewGuid().ToString('N')
$stagingRoot = Join-Path $evidenceRoot ('.native-evidence-stage-' + $transactionId)
$stagingDirectory = Join-Path $stagingRoot 'evidence'
$stagingIndex = Join-Path $stagingRoot 'index.json'
$backupDirectory = Join-Path $evidenceRoot ('.native-evidence-backup-dir-' + $transactionId)
$backupIndex = Join-Path $evidenceRoot ('.native-evidence-backup-index-' + $transactionId)
$backedUpDirectory = $false
$backedUpIndex = $false
$installedDirectory = $false
$installedIndex = $false
$transactionCommitted = $false

try {
    [void][IO.Directory]::CreateDirectory($stagingDirectory)
    if ($Gate -ceq 'ProductionAuthority') {
        $nativeDocuments = $authorityPackageDocuments
    } elseif ($Gate -ceq 'Vulcan' -and $vulcanPackageDocuments.Count -gt 0) {
        $nativeDocuments = $vulcanPackageDocuments
    } else {
        $nativeDocuments = [ordered]@{
            'report.json' = $reportDoc
            'binding.json' = $bindingDoc
        }
        if ($needsCommit) { $nativeDocuments['commit.json'] = $commitDoc }
    }
    if ($Gate -ceq 'Federation') {
        $nativeDocuments['visible-gui-attestation.json'] = $federationAttestationDoc
        $nativeDocuments['visible-gui-signing-request.json'] = $federationSigningRequestDoc
        $nativeDocuments['visible-gui.png'] = $federationScreenshotDoc
        $nativeDocuments['runtime-events.jsonl'] = $federationRuntimeLedgerDoc
        $nativeDocuments['post-run-receipt.json'] = $federationPostRunReceiptDoc
    }
    foreach ($nativeDocument in $nativeDocuments.GetEnumerator()) {
        [IO.File]::WriteAllBytes(
            (Join-Path $stagingDirectory ([string]$nativeDocument.Key)),
            [byte[]]$nativeDocument.Value.bytes)
    }
    if ($Gate -ceq 'ProductionAuthority') {
        $stagedArtifactDirectory = Join-Path $stagingDirectory 'artifacts'
        [void][IO.Directory]::CreateDirectory($stagedArtifactDirectory)
        foreach ($artifactDocument in $authorityPackagedArtifacts.GetEnumerator()) {
            [IO.File]::WriteAllBytes(
                (Join-Path $stagedArtifactDirectory ([string]$artifactDocument.Key)),
                [byte[]]$artifactDocument.Value.bytes)
        }
        $stagedValidationOutput = @(& $authorityValidator `
            -ValidatePackageRoot $stagingDirectory -ReleaseBundleRoot $ReleaseBundleRoot `
            -RequireCurrentlyValidReceipt)
        if (($stagedValidationOutput -join "`n") -cnotlike
                '*PRODUCTION_AUTHORITY_V4_PACKAGE_VALIDATION_PASS*') {
            throw 'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_STAGED_RAW_REVALIDATION_FAILED'
        }
    }

    $indexJson = (($index | ConvertTo-Json -Depth 12) -replace "`r`n","`n") + "`n"
    $indexBytes = $utf8NoBom.GetBytes($indexJson)
    [IO.File]::WriteAllBytes($stagingIndex, $indexBytes)

    # Re-verify the staged native bytes and descriptor values before touching a
    # previously published evidence set.
    foreach ($entry in @($index.canonical_evidence.PSObject.Properties)) {
        $leaf = [IO.Path]::GetFileName([string]$entry.Value.path)
        if ([string]::IsNullOrWhiteSpace($leaf) -or -not $nativeDocuments.Contains($leaf)) {
            throw "MCACE_NATIVE_EVIDENCE_STAGING_DESCRIPTOR_LEAF_INVALID|$($entry.Name)"
        }
        $staged = Join-Path $stagingDirectory $leaf
        $stagedBytes = [IO.File]::ReadAllBytes($staged)
        if ([long]$stagedBytes.Length -ne [long]$entry.Value.size_bytes -or
                (Get-BytesSha256 $stagedBytes) -cne [string]$entry.Value.sha256) {
            throw "MCACE_NATIVE_EVIDENCE_STAGING_VERIFICATION_FAILED|$($entry.Name)"
        }
    }
    if ($Gate -ceq 'ProductionAuthority') {
        foreach ($entry in @($index.packaged_artifacts.PSObject.Properties)) {
            $leaf = [IO.Path]::GetFileName([string]$entry.Value.path)
            if ([string]::IsNullOrWhiteSpace($leaf) -or
                    -not $authorityPackagedArtifacts.Contains($leaf)) {
                throw "MCACE_NATIVE_EVIDENCE_STAGING_ARTIFACT_DESCRIPTOR_INVALID|$($entry.Name)"
            }
            $stagedBytes = [IO.File]::ReadAllBytes((Join-Path $stagedArtifactDirectory $leaf))
            if ([long]$stagedBytes.Length -ne [long]$entry.Value.size_bytes -or
                    (Get-BytesSha256 $stagedBytes) -cne [string]$entry.Value.sha256) {
                throw "MCACE_NATIVE_EVIDENCE_STAGING_ARTIFACT_VERIFICATION_FAILED|$($entry.Name)"
            }
        }
    }
    $null = ConvertFrom-StrictJsonRaw ($utf8Strict.GetString([IO.File]::ReadAllBytes($stagingIndex)))

    if (Test-Path -LiteralPath $finalDirectory) {
        [IO.Directory]::Move($finalDirectory, $backupDirectory)
        $backedUpDirectory = $true
    }
    if (Test-Path -LiteralPath $finalIndex) {
        [IO.File]::Move($finalIndex, $backupIndex)
        $backedUpIndex = $true
    }

    [IO.Directory]::Move($stagingDirectory, $finalDirectory)
    $installedDirectory = $true
    [IO.File]::Move($stagingIndex, $finalIndex)
    $installedIndex = $true
    $transactionCommitted = $true

    # Backup cleanup occurs only after the index cutover. Failure to remove an
    # old backup must not roll a successful publication back into a mixed
    # generation; the finally block retries cleanup on a best-effort basis.
    if ($backedUpDirectory) { Remove-Item -LiteralPath $backupDirectory -Recurse -Force -ErrorAction SilentlyContinue }
    if ($backedUpIndex) { Remove-Item -LiteralPath $backupIndex -Force -ErrorAction SilentlyContinue }
} catch {
    $failure = $_
    $rollbackErrors = New-Object 'Collections.Generic.List[string]'
    foreach ($rollbackStep in @(
            [pscustomobject]@{ name = 'remove-new-index'; action = {
                    if ($installedIndex -and (Test-Path -LiteralPath $finalIndex -PathType Leaf)) {
                        Remove-Item -LiteralPath $finalIndex -Force -ErrorAction Stop
                    }
                } },
            [pscustomobject]@{ name = 'remove-new-directory'; action = {
                    if ($installedDirectory -and (Test-Path -LiteralPath $finalDirectory -PathType Container)) {
                        Remove-Item -LiteralPath $finalDirectory -Recurse -Force -ErrorAction Stop
                    }
                } },
            [pscustomobject]@{ name = 'restore-index'; action = {
                    if ($backedUpIndex -and (Test-Path -LiteralPath $backupIndex -PathType Leaf)) {
                        [IO.File]::Move($backupIndex, $finalIndex)
                    }
                } },
            [pscustomobject]@{ name = 'restore-directory'; action = {
                    if ($backedUpDirectory -and (Test-Path -LiteralPath $backupDirectory -PathType Container)) {
                        [IO.Directory]::Move($backupDirectory, $finalDirectory)
                    }
                } })) {
        try { & $rollbackStep.action }
        catch { [void]$rollbackErrors.Add("$($rollbackStep.name): $($_.Exception.Message)") }
    }
    if ($rollbackErrors.Count -gt 0) {
        throw "MCACE_NATIVE_EVIDENCE_ROLLBACK_INCOMPLETE|original=$($failure.Exception.Message)|rollback=$($rollbackErrors -join ' || ')|backup_directory=$backupDirectory|backup_index=$backupIndex"
    }
    throw $failure
} finally {
    if (Test-Path -LiteralPath $stagingRoot) { Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue }
    if ($transactionCommitted) {
        if (Test-Path -LiteralPath $backupDirectory) { Remove-Item -LiteralPath $backupDirectory -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $backupIndex) { Remove-Item -LiteralPath $backupIndex -Force -ErrorAction SilentlyContinue }
    }
}

$indexRelative = "$evidenceRootRelative/$EvidenceId.json"
Write-Output "MCACE_NATIVE_RELEASE_EVIDENCE_PUBLISHED|gate=$Gate|index=$indexRelative|directory=$nativePrefix"
} finally {
    Exit-NativeEvidencePublishMutex $publishMutex
}
