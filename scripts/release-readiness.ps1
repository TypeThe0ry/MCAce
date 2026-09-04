[CmdletBinding()]
param(
    [string]$SourceCommit,
    [string]$ReportPath,
    [string]$VisibleGuiTrustRootPath,
    [string]$ExpectedVisibleGuiTrustRootSha256,
    [string]$PostRunSupervisorTrustRootPath,
    [string]$ExpectedPostRunSupervisorTrustRootSha256,
    [string]$MatrixSupervisorTrustRootPath,
    [string]$ExpectedMatrixSupervisorTrustRootSha256,
    [string]$VulcanSupervisorTrustRootPath,
    [string]$ExpectedVulcanSupervisorTrustRootSha256,
    [string]$ReleaseBundleRoot = 'build/release-bundle',
    [ValidateRange(1, 10080)]
    [int]$MaximumEvidenceAgeMinutes = 1440
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$evidenceRootRelative = 'docs/evidence'

function ConvertTo-AbsoluteRepoPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}

function Get-RepoHead {
    $value = (& git -C $repoRoot rev-parse HEAD 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or $value -notmatch '^[0-9a-f]{40}$') {
        throw 'MCACE_RELEASE_READINESS_GIT_HEAD_UNAVAILABLE'
    }
    return $value.ToLowerInvariant()
}

function Get-RepoStatus { return @(& git -C $repoRoot status --porcelain 2>$null) }
function Test-StringEqual([object]$Value, [string]$Expected) {
    return $null -ne $Value -and $Value -is [string] -and [string]$Value -ceq $Expected
}
function Test-JsonBoolean([object]$Value) { return $Value -is [bool] }
function Test-True([object]$Value) { return (Test-JsonBoolean $Value) -and [bool]$Value }
function Test-False([object]$Value) { return (Test-JsonBoolean $Value) -and -not [bool]$Value }
function Test-JsonInteger([object]$Value) {
    return $Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64]
}
function Test-JsonArray([object]$Value) { return $Value -is [Array] }
function Test-Sha256([object]$Value) { return $Value -is [string] -and [string]$Value -cmatch '^[0-9a-f]{64}$' }
function Test-Sha1([object]$Value) { return $Value -is [string] -and [string]$Value -cmatch '^[0-9a-f]{40}$' }
function Test-Commit([object]$Value) { return $Value -is [string] -and [string]$Value -cmatch '^[0-9a-f]{40}$' }
function Test-NonEmptyJsonString([object]$Value) {
    return $Value -is [string] -and -not [string]::IsNullOrWhiteSpace([string]$Value)
}

function Get-ExactPropertyNames([object]$Value) {
    if ($null -eq $Value) { return @() }
    return @($Value.PSObject.Properties | ForEach-Object Name)
}

function Test-ExactProperties([object]$Value, [string[]]$Expected) {
    if ($null -eq $Value) { return $false }
    $actual = @(Get-ExactPropertyNames $Value | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    return $actual.Count -eq $wanted.Count -and (($actual -join "`n") -ceq ($wanted -join "`n"))
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

function ConvertFrom-StrictJsonRaw([string]$Raw) {
    if ([string]::IsNullOrWhiteSpace($Raw)) { throw 'MCACE_RELEASE_EVIDENCE_JSON_EMPTY' }
    $trimmed = $Raw.Trim()
    if ($trimmed.Length -lt 2 -or $trimmed[0] -cne '{' -or $trimmed[$trimmed.Length - 1] -cne '}') {
        throw 'MCACE_RELEASE_EVIDENCE_TOP_LEVEL_OBJECT_REQUIRED'
    }
    $command = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
    if ($command.Parameters.ContainsKey('DateKind')) {
        $value = ConvertFrom-Json -InputObject $Raw -DateKind String -ErrorAction Stop
    } else {
        $value = ConvertFrom-Json -InputObject $Raw -ErrorAction Stop
    }
    # ConvertFrom-Json collapses duplicate same-case keys. Compare every lexical
    # object-property token with the recursively materialized property count.
    $propertyTokens = [regex]::Matches(
        $Raw,
        '(?:\{|,)\s*"(?:\\["\\/bfnrt]|\\u[0-9a-fA-F]{4}|[^"\\])*"\s*:',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
    if ($propertyTokens -ne (Get-JsonGraphPropertyCount $value)) {
        throw 'MCACE_RELEASE_EVIDENCE_DUPLICATE_OR_AMBIGUOUS_PROPERTY'
    }
    return $value
}

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Get-BytesSha256([byte[]]$Bytes) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hasher.Dispose() }
}

function Test-ReleaseWindowsPlatform {
    if (Get-Variable IsWindows -ErrorAction SilentlyContinue) { return [bool]$IsWindows }
    return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

function Initialize-ReleaseFileIdentityApi {
    if (-not (Test-ReleaseWindowsPlatform) -or
            ('MCAceReleaseReadinessFileIdentityV3' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class MCAceReleaseReadinessFileIdentityV3 {
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

function Assert-ReleasePathChainNoReparse([string]$AbsolutePath, [bool]$LeafMustExist) {
    $full = [IO.Path]::GetFullPath($AbsolutePath)
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root)) { throw 'MCACE_RELEASE_PATH_ROOT_INVALID' }
    $segments = @($full.Substring($root.Length).Split(
        @([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar),
        [StringSplitOptions]::RemoveEmptyEntries))
    $cursor = $root
    for ($index = 0; $index -lt $segments.Count; $index++) {
        $cursor = Join-Path $cursor $segments[$index]
        if (-not (Test-Path -LiteralPath $cursor)) {
            if ($LeafMustExist -or $index -lt ($segments.Count - 1)) {
                throw 'MCACE_RELEASE_PATH_COMPONENT_MISSING'
            }
            return
        }
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($item.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $item.LinkType)) {
            throw 'MCACE_RELEASE_EVIDENCE_REPARSE_PATH_REJECTED'
        }
    }
}

function Get-ReleaseNoFollowFileIdentity([string]$Path, [switch]$Directory) {
    if (Test-ReleaseWindowsPlatform) {
        Initialize-ReleaseFileIdentityApi
        try { return [MCAceReleaseReadinessFileIdentityV3]::NoFollow($Path, [bool]$Directory) }
        catch { throw "MCACE_RELEASE_NOFOLLOW_IDENTITY_FAILED|$($_.Exception.Message)" }
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($item.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $item.LinkType)) {
        throw 'MCACE_RELEASE_NOFOLLOW_REPARSE_REJECTED'
    }
    return "portable:$($item.FullName):$([long]$item.Length):$($item.LastWriteTimeUtc.Ticks)"
}

function Read-ReleaseLockedFileBytes(
        [string]$Path,
        [long]$MinimumBytes,
        [long]$MaximumBytes,
        [string]$Role) {
    $absolute = [IO.Path]::GetFullPath($Path)
    Assert-ReleasePathChainNoReparse $absolute $true
    if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) {
        throw "MCACE_RELEASE_FILE_REQUIRED|$Role"
    }
    $before = Get-ReleaseNoFollowFileIdentity $absolute
    $stream = New-Object IO.FileStream(
        $absolute, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $length = [long]$stream.Length
        if ($length -lt $MinimumBytes -or $length -gt $MaximumBytes -or $length -gt [int]::MaxValue) {
            throw "MCACE_RELEASE_FILE_SIZE_INVALID|$Role"
        }
        $bytes = New-Object byte[] ([int]$length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw "MCACE_RELEASE_FILE_SHORT_READ|$Role" }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1 -or $stream.Length -ne $length) {
            throw "MCACE_RELEASE_FILE_CHANGED_DURING_READ|$Role"
        }
        if (Test-ReleaseWindowsPlatform) {
            try { $handleIdentity = [MCAceReleaseReadinessFileIdentityV3]::FromHandle($stream.SafeFileHandle) }
            catch { throw "MCACE_RELEASE_HANDLE_IDENTITY_FAILED|$Role|$($_.Exception.Message)" }
            if ($handleIdentity -cne $before) { throw "MCACE_RELEASE_HANDLE_IDENTITY_CHANGED|$Role" }
        }
        if ((Get-ReleaseNoFollowFileIdentity $absolute) -cne $before) {
            throw "MCACE_RELEASE_PATH_IDENTITY_CHANGED|$Role"
        }
    } finally { $stream.Dispose() }
    Assert-ReleasePathChainNoReparse $absolute $true
    return [pscustomobject]@{
        absolute=$absolute; identity=$before; bytes=$bytes; size=[long]$bytes.Length
        size_bytes=[long]$bytes.Length; sha256=Get-BytesSha256 $bytes
    }
}
function ConvertFrom-StrictTextBytes([byte[]]$Bytes) {
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { throw 'MCACE_RELEASE_TEXT_EMPTY' }
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
        return [Text.UnicodeEncoding]::new($false, $true, $true).GetString($Bytes, 2, $Bytes.Length - 2)
    }
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) {
        return [Text.UnicodeEncoding]::new($true, $true, $true).GetString($Bytes, 2, $Bytes.Length - 2)
    }
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        return [Text.UTF8Encoding]::new($true, $true).GetString($Bytes, 3, $Bytes.Length - 3)
    }
    return [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
}
function Get-CompactObjectSha256([object]$Value, [int]$Depth = 40) {
    $json = ($Value | ConvertTo-Json -Depth $Depth -Compress) + "`n"
    return Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($json))
}

function ConvertTo-EvidenceTime([object]$Value) {
    if ($Value -is [DateTimeOffset]) { return [DateTimeOffset]$Value }
    if ($Value -is [DateTime]) { return [DateTimeOffset]([DateTime]$Value) }
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        throw 'MCACE_RELEASE_EVIDENCE_TIMESTAMP_INVALID'
    }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            [string]$Value, 'o', [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None, [ref]$parsed)) {
        throw 'MCACE_RELEASE_EVIDENCE_TIMESTAMP_INVALID'
    }
    return $parsed
}
function Test-SameEvidenceTime([object]$Left, [object]$Right) {
    try { return (ConvertTo-EvidenceTime $Left).ToUniversalTime().Ticks -eq (ConvertTo-EvidenceTime $Right).ToUniversalTime().Ticks }
    catch { return $false }
}

function Assert-FreshEvidenceTime([object]$Value) {
    $timestamp = (ConvertTo-EvidenceTime $Value).ToUniversalTime()
    $age = [DateTimeOffset]::UtcNow - $timestamp
    if ($age.TotalMinutes -lt -5 -or $age.TotalMinutes -gt $MaximumEvidenceAgeMinutes) {
        throw "MCACE_RELEASE_EVIDENCE_STALE_OR_FUTURE|generated_at=$($timestamp.ToString('o'))|maximum_minutes=$MaximumEvidenceAgeMinutes"
    }
    return $timestamp
}

function Assert-CanonicalRepoRelativePath([string]$Relative, [string]$Prefix, [string]$ExpectedLeaf) {
    if ([string]::IsNullOrWhiteSpace($Relative) -or $Relative.Contains('\') -or
            $Relative.StartsWith('/') -or $Relative.Contains(':')) {
        throw 'MCACE_RELEASE_EVIDENCE_PATH_INVALID'
    }
    $segments = @($Relative.Split('/'))
    if (@($segments | Where-Object { $_ -in @('', '.', '..') }).Count -ne 0 -or
            (-not [string]::IsNullOrEmpty($Prefix) -and
                -not $Relative.StartsWith(($Prefix.TrimEnd('/') + '/'), [StringComparison]::Ordinal)) -or
            (-not [string]::IsNullOrEmpty($ExpectedLeaf) -and $segments[-1] -cne $ExpectedLeaf)) {
        throw 'MCACE_RELEASE_EVIDENCE_PATH_OUT_OF_SCOPE'
    }
    $absolute = [IO.Path]::GetFullPath((Join-Path $repoRoot $Relative))
    $rootPrefix = $repoRoot.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    if (-not $absolute.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $absolute -PathType Leaf)) {
        throw 'MCACE_RELEASE_EVIDENCE_FILE_REQUIRED'
    }
    $cursor = $repoRoot
    foreach ($segment in $segments) {
        $cursor = Join-Path $cursor $segment
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'MCACE_RELEASE_EVIDENCE_REPARSE_PATH_REJECTED'
        }
    }
    $tracked = @(& git -C $repoRoot ls-files --error-unmatch -- $Relative 2>$null)
    if ($LASTEXITCODE -ne 0 -or $tracked.Count -ne 1 -or [string]$tracked[0] -cne $Relative) {
        throw 'MCACE_RELEASE_EVIDENCE_MUST_BE_GIT_TRACKED'
    }
    return $absolute
}

function Read-StrictRepoJson([string]$Relative, [string]$Prefix, [string]$ExpectedLeaf = '') {
    $absolute = Assert-CanonicalRepoRelativePath $Relative $Prefix $ExpectedLeaf
    $artifact = Read-ReleaseLockedFileBytes $absolute 1 2097152 'TRACKED_JSON'
    $bytes = $artifact.bytes
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        throw 'MCACE_RELEASE_EVIDENCE_UTF8_BOM_REJECTED'
    }
    $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    return [pscustomobject]@{
        relative=$Relative; absolute=$absolute; bytes=$bytes; size=[long]$bytes.Length
        size_bytes=[long]$bytes.Length; sha256=$artifact.sha256
        raw=$raw; value=ConvertFrom-StrictJsonRaw $raw
    }
}

function Read-StrictAbsoluteJson([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $artifact = Read-ReleaseLockedFileBytes ([IO.Path]::GetFullPath($Path)) 1 2097152 'JSON'
    if ($artifact.bytes.Length -ge 3 -and $artifact.bytes[0] -eq 0xEF -and
            $artifact.bytes[1] -eq 0xBB -and $artifact.bytes[2] -eq 0xBF) {
        throw 'MCACE_RELEASE_JSON_UTF8_BOM_REJECTED'
    }
    return ConvertFrom-StrictJsonRaw (
        [Text.UTF8Encoding]::new($false, $true).GetString($artifact.bytes))
}

function Assert-ExactEvidenceDirectory([string]$Prefix, [string[]]$ExpectedFiles) {
    if ([string]::IsNullOrWhiteSpace($Prefix) -or $Prefix.Contains('\') -or
            $Prefix.StartsWith('/') -or $Prefix.Contains(':')) {
        throw 'MCACE_RELEASE_EVIDENCE_DIRECTORY_PATH_INVALID'
    }
    $segments = @($Prefix.Split('/'))
    if (@($segments | Where-Object { $_ -in @('', '.', '..') }).Count -ne 0 -or
            -not $Prefix.StartsWith(($evidenceRootRelative + '/'), [StringComparison]::Ordinal)) {
        throw 'MCACE_RELEASE_EVIDENCE_DIRECTORY_OUT_OF_SCOPE'
    }
    $absolute = [IO.Path]::GetFullPath((Join-Path $repoRoot $Prefix))
    if (-not (Test-Path -LiteralPath $absolute -PathType Container)) {
        throw 'MCACE_RELEASE_EVIDENCE_DIRECTORY_REQUIRED'
    }
    $cursor = $repoRoot
    foreach ($segment in $segments) {
        $cursor = Join-Path $cursor $segment
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'MCACE_RELEASE_EVIDENCE_REPARSE_PATH_REJECTED'
        }
    }
    $children = @(Get-ChildItem -LiteralPath $absolute -Force)
    if (@($children | Where-Object {
                $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
            }).Count -ne 0) {
        throw 'MCACE_RELEASE_EVIDENCE_DIRECTORY_NESTED_OR_REPARSE_ENTRY_REJECTED'
    }
    $actual = @($children | ForEach-Object Name | Sort-Object)
    $expected = @($ExpectedFiles | Sort-Object)
    if ($actual.Count -ne $expected.Count -or (($actual -join "`n") -cne ($expected -join "`n"))) {
        throw 'MCACE_RELEASE_EVIDENCE_DIRECTORY_FILE_SET_INVALID'
    }
}

function Assert-CurrentTrackedFileHash([string]$Relative, [object]$ExpectedSha256) {
    if (-not (Test-Sha256 $ExpectedSha256)) {
        throw 'MCACE_RELEASE_SOURCE_BINDING_HASH_INVALID'
    }
    $absolute = Assert-CanonicalRepoRelativePath $Relative '' (@($Relative.Split('/'))[-1])
    if ((Get-FileSha256 $absolute) -cne [string]$ExpectedSha256) {
        throw "MCACE_RELEASE_SOURCE_BINDING_HASH_MISMATCH|$Relative"
    }
}

function Assert-ArtifactDescriptor([object]$Descriptor, [string]$ExpectedPath, [string]$Prefix) {
    if (-not (Test-ExactProperties $Descriptor @('path','sha256','size_bytes')) -or
            -not (Test-StringEqual $Descriptor.path $ExpectedPath) -or
            -not (Test-Sha256 $Descriptor.sha256) -or
            -not (Test-JsonInteger $Descriptor.size_bytes) -or [long]$Descriptor.size_bytes -le 0) {
        throw 'MCACE_RELEASE_EVIDENCE_DESCRIPTOR_INVALID'
    }
    $absolute = Assert-CanonicalRepoRelativePath $ExpectedPath $Prefix (@($ExpectedPath.Split('/'))[-1])
    $artifact = Read-ReleaseLockedFileBytes $absolute 1 20971520 'EVIDENCE_DESCRIPTOR'
    if ([long]$artifact.size_bytes -ne [long]$Descriptor.size_bytes -or
            [string]$artifact.sha256 -cne [string]$Descriptor.sha256) {
        throw 'MCACE_RELEASE_EVIDENCE_DESCRIPTOR_HASH_OR_SIZE_MISMATCH'
    }
    return [pscustomobject]@{
        relative=$ExpectedPath; absolute=$absolute; bytes=$artifact.bytes
        size=[long]$artifact.size_bytes; size_bytes=[long]$artifact.size_bytes
        sha256=[string]$Descriptor.sha256
    }
}
function Read-JsonDescriptor([object]$Descriptor, [string]$ExpectedPath, [string]$Prefix) {
    $artifact = Assert-ArtifactDescriptor $Descriptor $ExpectedPath $Prefix
    if ($artifact.size -gt 2097152) { throw 'MCACE_RELEASE_EVIDENCE_SIZE_INVALID' }
    $raw = [Text.UTF8Encoding]::new($false, $true).GetString($artifact.bytes)
    return [pscustomobject]@{
        relative=$artifact.relative; absolute=$artifact.absolute; bytes=$artifact.bytes
        size=$artifact.size; size_bytes=$artifact.size_bytes; sha256=$artifact.sha256
        raw=$raw; value=ConvertFrom-StrictJsonRaw $raw
    }
}

function Read-BinaryDescriptor([object]$Descriptor, [string]$ExpectedPath, [string]$Prefix) {
    $artifact = Assert-ArtifactDescriptor $Descriptor $ExpectedPath $Prefix
    if ($artifact.size -lt 128 -or $artifact.size -gt 20971520) {
        throw 'MCACE_RELEASE_BINARY_EVIDENCE_SIZE_INVALID'
    }
    return $artifact
}

function Get-PngUInt32([byte[]]$Bytes, [int]$Offset) {
    if ($Offset -lt 0 -or $Offset + 4 -gt $Bytes.Length) {
        throw 'MCACE_RELEASE_PNG_TRUNCATED'
    }
    return [uint32](([uint32]$Bytes[$Offset] -shl 24) -bor
        ([uint32]$Bytes[$Offset + 1] -shl 16) -bor
        ([uint32]$Bytes[$Offset + 2] -shl 8) -bor [uint32]$Bytes[$Offset + 3])
}

function Assert-PngDescriptor([object]$Document) {
    $signature = [byte[]](0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a)
    if ($Document.bytes.Length -lt 33) { throw 'MCACE_RELEASE_PNG_TRUNCATED' }
    for ($index = 0; $index -lt $signature.Length; $index++) {
        if ($Document.bytes[$index] -ne $signature[$index]) {
            throw 'MCACE_RELEASE_PNG_SIGNATURE_INVALID'
        }
    }
    if ((Get-PngUInt32 $Document.bytes 8) -ne 13 -or
            [Text.Encoding]::ASCII.GetString($Document.bytes, 12, 4) -cne 'IHDR') {
        throw 'MCACE_RELEASE_PNG_IHDR_INVALID'
    }
    $width = [long](Get-PngUInt32 $Document.bytes 16)
    $height = [long](Get-PngUInt32 $Document.bytes 20)
    if ($width -lt 320 -or $width -gt 16384 -or $height -lt 200 -or $height -gt 16384) {
        throw 'MCACE_RELEASE_PNG_DIMENSIONS_INVALID'
    }
    return [pscustomobject]@{ width=[int]$width; height=[int]$height }
}

function Assert-FederationSanitizedJsonRaw([string]$Raw, [string]$Role) {
    if ($Raw -match '(?i)[A-Z]:[\\/]|\\\\|(?:^|["\s])/(?!/)[^"\r\n]*' -or
            $Raw -match '(?i)private.?key|client.?secret|access.?token|raw.?grant|raw.?presentation') {
        throw "MCACE_RELEASE_FEDERATION_SENSITIVE_OR_ABSOLUTE_VALUE_REJECTED|$Role"
    }
}

function Read-VisibleGuiTrustRootEvidence([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'MCACE_RELEASE_FEDERATION_GUI_TRUST_ROOT_REQUIRED'
    }
    $absolute = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else { [IO.Path]::GetFullPath((Join-Path $repoRoot $Path)) }
    $repoPrefix = $repoRoot.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    if ($absolute.Equals($repoRoot, [StringComparison]::OrdinalIgnoreCase) -or
            $absolute.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'MCACE_RELEASE_FEDERATION_GUI_TRUST_ROOT_MUST_BE_OUT_OF_BAND'
    }
    $artifact = Read-ReleaseLockedFileBytes $absolute 64 1048576 'VISIBLE_GUI_TRUST_ROOT'
    if ($artifact.bytes.Length -ge 3 -and $artifact.bytes[0] -eq 0xEF -and
            $artifact.bytes[1] -eq 0xBB -and $artifact.bytes[2] -eq 0xBF) {
        throw 'MCACE_RELEASE_FEDERATION_GUI_TRUST_ROOT_UTF8_BOM_REJECTED'
    }
    $raw = [Text.UTF8Encoding]::new($false, $true).GetString($artifact.bytes)
    return [pscustomobject]@{
        absolute=$artifact.absolute; bytes=$artifact.bytes; raw=$raw
        size=$artifact.size_bytes; size_bytes=$artifact.size_bytes; sha256=$artifact.sha256
        value=ConvertFrom-StrictJsonRaw $raw
    }
}

function Read-PostRunSupervisorTrustRootEvidence([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'MCACE_RELEASE_FEDERATION_POSTRUN_TRUST_ROOT_REQUIRED'
    }
    $absolute = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else { [IO.Path]::GetFullPath((Join-Path $repoRoot $Path)) }
    $repoPrefix = $repoRoot.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    if ($absolute.Equals($repoRoot, [StringComparison]::OrdinalIgnoreCase) -or
            $absolute.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'MCACE_RELEASE_FEDERATION_POSTRUN_TRUST_ROOT_MUST_BE_OUT_OF_BAND'
    }
    $artifact = Read-ReleaseLockedFileBytes $absolute 64 1048576 'POSTRUN_SUPERVISOR_TRUST_ROOT'
    if ($artifact.bytes.Length -ge 3 -and $artifact.bytes[0] -eq 0xEF -and
            $artifact.bytes[1] -eq 0xBB -and $artifact.bytes[2] -eq 0xBF) {
        throw 'MCACE_RELEASE_FEDERATION_POSTRUN_TRUST_ROOT_UTF8_BOM_REJECTED'
    }
    $raw = [Text.UTF8Encoding]::new($false, $true).GetString($artifact.bytes)
    return [pscustomobject]@{
        absolute=$artifact.absolute; bytes=$artifact.bytes; raw=$raw
        size=$artifact.size_bytes; size_bytes=$artifact.size_bytes; sha256=$artifact.sha256
        value=ConvertFrom-StrictJsonRaw $raw
    }
}

function Read-VulcanSupervisorTrustRootEvidence([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'MCACE_RELEASE_VULCAN_SUPERVISOR_TRUST_ROOT_REQUIRED'
    }
    $absolute = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else { [IO.Path]::GetFullPath((Join-Path $repoRoot $Path)) }
    $repoPrefix = $repoRoot.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    if ($absolute.Equals($repoRoot,[StringComparison]::OrdinalIgnoreCase) -or
            $absolute.StartsWith($repoPrefix,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'MCACE_RELEASE_VULCAN_SUPERVISOR_TRUST_ROOT_MUST_BE_OUT_OF_BAND'
    }
    $artifact = Read-ReleaseLockedFileBytes $absolute 64 1048576 'VULCAN_SUPERVISOR_TRUST_ROOT'
    if ($artifact.bytes.Length -ge 3 -and $artifact.bytes[0] -eq 0xEF -and
            $artifact.bytes[1] -eq 0xBB -and $artifact.bytes[2] -eq 0xBF) {
        throw 'MCACE_RELEASE_VULCAN_SUPERVISOR_TRUST_ROOT_UTF8_BOM_REJECTED'
    }
    $raw=[Text.UTF8Encoding]::new($false,$true).GetString($artifact.bytes)
    return [pscustomobject]@{
        absolute=$artifact.absolute;bytes=$artifact.bytes;raw=$raw
        size=$artifact.size_bytes;size_bytes=$artifact.size_bytes;sha256=$artifact.sha256
        value=ConvertFrom-StrictJsonRaw $raw
    }
}

function Get-ReadinessAstFunctionText(
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
            throw "MCACE_RELEASE_FEDERATION_VALIDATOR_FUNCTION_INVALID|$name"
        }
        $parts.Add($matches[0].Extent.Text)
    }
    return $parts -join "`n`n"
}

function Get-ReadinessAstAssignmentText(
        [Management.Automation.Language.Ast]$Root,
        [string]$VariableText) {
    $matches = @($Root.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq $VariableText
    }, $true))
    if ($matches.Count -ne 1) {
        throw "MCACE_RELEASE_FEDERATION_VALIDATOR_ASSIGNMENT_INVALID|$VariableText"
    }
    return $matches[0].Right.Extent.Text
}

function New-ReadinessFederationV5ValidatorModule {
    $wrapper = Join-Path $PSScriptRoot 'fabric-federation-gui-handoff-smoke.ps1'
    $platform = Join-Path $PSScriptRoot 'platform-load-smoke.ps1'
    $wrapperTokens = $null; $wrapperErrors = $null
    $platformTokens = $null; $platformErrors = $null
    $wrapperAst = [Management.Automation.Language.Parser]::ParseFile(
        $wrapper, [ref]$wrapperTokens, [ref]$wrapperErrors)
    $platformAst = [Management.Automation.Language.Parser]::ParseFile(
        $platform, [ref]$platformTokens, [ref]$platformErrors)
    if (@($wrapperErrors).Count -ne 0 -or @($platformErrors).Count -ne 0) {
        throw 'MCACE_RELEASE_FEDERATION_VALIDATOR_PARSE_FAILED'
    }
    $platformFunctions = Get-ReadinessAstFunctionText $platformAst @(
        'Get-BytesSha256','Get-JsonPropertyNames','Test-ExactJsonProperties',
        'Test-JsonInteger','Assert-DirectLocalPath')
    $wrapperFunctions = Get-ReadinessAstFunctionText $wrapperAst @(
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
`$visibleGuiSigningRequestPropertyNames = $(Get-ReadinessAstAssignmentText $wrapperAst '$visibleGuiSigningRequestPropertyNames')
`$visibleGuiAttestationPropertyNames = $(Get-ReadinessAstAssignmentText $wrapperAst '$visibleGuiAttestationPropertyNames')
`$visibleGuiTrustRootPropertyNames = $(Get-ReadinessAstAssignmentText $wrapperAst '$visibleGuiTrustRootPropertyNames')
`$postRunTrustRootPropertyNames = $(Get-ReadinessAstAssignmentText $wrapperAst '$postRunTrustRootPropertyNames')
`$postRunReceiptPropertyNames = $(Get-ReadinessAstAssignmentText $wrapperAst '$postRunReceiptPropertyNames')
`$runtimeEventPropertyNames = $(Get-ReadinessAstAssignmentText $wrapperAst '$runtimeEventPropertyNames')
`$reportPropertyNames = $(Get-ReadinessAstAssignmentText $wrapperAst '$reportPropertyNames')
`$fabricTargets = [ordered]@{
    '1.21.11' = [ordered]@{
        minecraft_version='1.21.11'; fabric_api_version='0.141.6+1.21.11'; java_major=21
        artifact_kind='FINAL_REMAP_JAR'; runtime_mode='LOOM_FINAL_REMAP_ARTIFACT'
    }
    '26.1.2' = [ordered]@{
        minecraft_version='26.1.2'; fabric_api_version='0.155.2+26.1.2'; java_major=25
        artifact_kind='FINAL_NAMED_JAR'; runtime_mode='LOOM_FINAL_NAMED_JAR_ARTIFACT'
    }
    '26.2' = [ordered]@{
        minecraft_version='26.2'; fabric_api_version='0.157.0+26.2'; java_major=25
        artifact_kind='FINAL_NAMED_JAR'; runtime_mode='LOOM_FINAL_NAMED_JAR_ARTIFACT'
    }
}

"@
    return New-Module -ScriptBlock ([scriptblock]::Create(
        $header + "`n" + $platformFunctions + "`n" + $wrapperFunctions))
}

function New-ReadinessVulcanV3ValidatorModule {
    $wrapper=Join-Path $PSScriptRoot 'vulcan-genuine-event-smoke.ps1'
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($wrapper,[ref]$tokens,[ref]$errors)
    if (@($errors).Count -ne 0) { throw 'MCACE_RELEASE_VULCAN_V3_VALIDATOR_PARSE_FAILED' }
    $functions=Get-ReadinessAstFunctionText $ast @(
        'ConvertTo-Sha256','Get-BytesSha256','ConvertFrom-StrictUtcInstant',
        'Assert-DirectLocalPath','Assert-SanitizedEvidence','Test-JsonBoolean',
        'Test-JsonInteger','Test-JsonArray','Get-JsonGraphPropertyCount',
        'Assert-NoCaseAmbiguousJsonProperties',
        'ConvertFrom-StrictJsonRaw','Get-JsonPropertyNames','Test-ExactProperties',
        'Test-RsaPkcs1Sha256Signature','Get-VulcanV3ReceiptSigningPayload',
        'Assert-VulcanV3TrustRoot','Open-LockedVulcanV3Evidence',
        'Assert-VulcanV3RawRiskEvent','Assert-VulcanV3CallbackLedger',
        'Assert-VulcanV3Receipt','Assert-VulcanV3Package')
    $header=@"
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
`$v3ReceiptPropertyNames=$(Get-ReadinessAstAssignmentText $ast '$v3ReceiptPropertyNames')
"@
    return New-Module -ScriptBlock ([scriptblock]::Create($header+"`n"+$functions))
}

function Read-PropertiesFile([string]$Path) {
    $resolved = ConvertTo-AbsoluteRepoPath $Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { return $null }
    $artifact = Read-ReleaseLockedFileBytes $resolved 2 1048576 'PROPERTIES'
    if ($artifact.bytes.Length -ge 3 -and $artifact.bytes[0] -eq 0xEF -and
            $artifact.bytes[1] -eq 0xBB -and $artifact.bytes[2] -eq 0xBF) {
        throw 'MCACE_RELEASE_PROPERTIES_UTF8_BOM_REJECTED'
    }
    $raw = [Text.UTF8Encoding]::new($false, $true).GetString($artifact.bytes)
    if ($raw.Contains("`r") -or -not $raw.EndsWith("`n")) {
        throw 'MCACE_RELEASE_PROPERTIES_CANONICAL_ENCODING_INVALID'
    }
    $properties = [ordered]@{}
    foreach ($line in @($raw.TrimEnd("`n") -split "`n")) {
        $text = [string]$line
        if ($text.Length -eq 0 -or $text -cne $text.Trim()) {
            throw 'MCACE_RELEASE_PROPERTIES_LINE_INVALID'
        }
        $separator = $text.IndexOf('=')
        if ($separator -lt 1) { throw 'MCACE_RELEASE_PROPERTIES_LINE_INVALID' }
        $key = $text.Substring(0, $separator)
        $value = $text.Substring($separator + 1)
        if ($key -cnotmatch '^[A-Za-z0-9._-]+$' -or $properties.Contains($key)) {
            throw 'MCACE_RELEASE_PROPERTIES_KEY_INVALID'
        }
        $properties[$key] = $value
    }
    return [pscustomobject]$properties
}

function Get-ReleaseArtifactSourceCommit {
    $relative = 'docs/evidence/release-artifact-source.txt'
    $absolute = Assert-CanonicalRepoRelativePath $relative $evidenceRootRelative `
        'release-artifact-source.txt'
    $artifact = Read-ReleaseLockedFileBytes $absolute 41 41 'RELEASE_ARTIFACT_SOURCE'
    if ($artifact.bytes[40] -ne 0x0A) {
        throw 'MCACE_RELEASE_ARTIFACT_SOURCE_CANONICAL_LINE_INVALID'
    }
    for ($index = 0; $index -lt 40; $index++) {
        $value = [int]$artifact.bytes[$index]
        if (-not (($value -ge 0x30 -and $value -le 0x39) -or
                ($value -ge 0x61 -and $value -le 0x66))) {
            throw 'MCACE_RELEASE_ARTIFACT_SOURCE_CANONICAL_LINE_INVALID'
        }
    }
    return [Text.Encoding]::ASCII.GetString($artifact.bytes, 0, 40)
}

function Test-ProtectedReleaseCiContext([string]$ExpectedCommit) {
    $workspace = try { [IO.Path]::GetFullPath([string]$env:GITHUB_WORKSPACE) } catch { '' }
    return [string]$env:CI -ceq 'true' -and [string]$env:GITHUB_ACTIONS -ceq 'true' -and
        [string]$env:GITHUB_SERVER_URL -ceq 'https://github.com' -and
        [string]$env:GITHUB_REPOSITORY -ceq 'TypeThe0ry/MCAce' -and
        [string]$env:GITHUB_EVENT_NAME -ceq 'push' -and
        ([string]$env:GITHUB_REF -ceq 'refs/heads/main' -or [string]$env:GITHUB_REF -ceq 'refs/tags/v0.0.1') -and
        [string]$env:GITHUB_REF_PROTECTED -ceq 'true' -and
        [string]$env:GITHUB_SHA -ceq $ExpectedCommit -and
        [string]$env:GITHUB_WORKFLOW_SHA -ceq $ExpectedCommit -and
        [string]$env:GITHUB_WORKFLOW_REF -ceq "TypeThe0ry/MCAce/.github/workflows/build.yml@$($env:GITHUB_REF)" -and
        [string]$env:GITHUB_JOB -ceq 'build' -and
        [string]$env:RUNNER_ENVIRONMENT -ceq 'github-hosted' -and [string]$env:RUNNER_OS -ceq 'Linux' -and
        [string]$env:GITHUB_RUN_ID -cmatch '^[1-9][0-9]*$' -and
        [string]$env:GITHUB_RUN_ATTEMPT -cmatch '^[1-9][0-9]*$' -and
        $workspace.Equals($repoRoot, [StringComparison]::Ordinal) -and
        [string]$env:MCACE_PROTECTED_RELEASE_CI -ceq 'true' -and
        [string]$env:MCACE_PROTECTED_RELEASE_ENVIRONMENT -ceq 'release'
}

function Assert-CompatibilityReport(
        [object]$Report,
        [string]$ExpectedCommit,
        [string]$ExpectedArtifactSourceCommit,
        [string]$BundleRoot) {
    $topNames = @('schema','generated_at','source_commit','artifact_source_commit',
        'target_count','exact_bundle_entry_count',
        'unsupported_versions_are_fail_closed','unsupported_examples','targets','passed')
    if (-not (Test-ExactProperties $Report $topNames) -or
            -not (Test-StringEqual $Report.schema 'MCACE_VERSION_COMPATIBILITY_CONTRACT_V2') -or
            -not (Test-StringEqual $Report.source_commit $ExpectedCommit) -or
            -not (Test-StringEqual $Report.artifact_source_commit $ExpectedArtifactSourceCommit) -or
            -not (Test-JsonInteger $Report.target_count) -or [int]$Report.target_count -ne 3 -or
            -not (Test-JsonInteger $Report.exact_bundle_entry_count) -or [int]$Report.exact_bundle_entry_count -ne 8 -or
            -not (Test-True $Report.unsupported_versions_are_fail_closed) -or -not (Test-True $Report.passed) -or
            -not (Test-JsonArray $Report.unsupported_examples) -or
            ((@($Report.unsupported_examples) -join ',') -cne '1.21.1,1.21.10,26.1,26.3') -or
            -not (Test-JsonArray $Report.targets) -or @($Report.targets).Count -ne 3) {
        throw 'MCACE_RELEASE_COMPATIBILITY_REPORT_INVALID'
    }
    $null = Assert-FreshEvidenceTime $Report.generated_at
    $expected = @(
        [pscustomobject]@{ version='1.21.11'; protocol=774; java=21; mode='FINAL_REMAP_JAR'; artifact='mcace-client-fabric-1.21.11.jar'; nested=5 },
        [pscustomobject]@{ version='26.1.2'; protocol=775; java=25; mode='FINAL_NAMED_JAR'; artifact='mcace-client-fabric-26.1.2.jar'; nested=1 },
        [pscustomobject]@{ version='26.2'; protocol=776; java=25; mode='FINAL_NAMED_JAR'; artifact='mcace-client-fabric-26.2.jar'; nested=1 }
    )
    for ($i = 0; $i -lt 3; $i++) {
        $target = @($Report.targets)[$i]
        $want = $expected[$i]
        if (-not (Test-ExactProperties $target @('minecraft_version','protocol','java_major','artifact_mode','artifact','sha256','nested_jar_count','passed')) -or
                -not (Test-StringEqual $target.minecraft_version $want.version) -or
                -not (Test-JsonInteger $target.protocol) -or [int]$target.protocol -ne $want.protocol -or
                -not (Test-JsonInteger $target.java_major) -or [int]$target.java_major -ne $want.java -or
                -not (Test-StringEqual $target.artifact_mode $want.mode) -or
                -not (Test-StringEqual $target.artifact $want.artifact) -or
                -not (Test-Sha256 $target.sha256) -or
                -not (Test-JsonInteger $target.nested_jar_count) -or [int]$target.nested_jar_count -ne $want.nested -or
                -not (Test-True $target.passed)) {
            throw 'MCACE_RELEASE_COMPATIBILITY_TARGET_INVALID'
        }
        $artifactDoc = Read-ReleaseLockedFileBytes (Join-Path $BundleRoot $want.artifact) `
            1024 134217728 'COMPATIBILITY_TARGET_JAR'
        if ([string]$artifactDoc.sha256 -cne [string]$target.sha256) {
            throw 'MCACE_RELEASE_COMPATIBILITY_TARGET_HASH_INVALID'
        }
    }
}

function Test-ExactReleaseBundleEntrySet([string]$Root, [string[]]$ExpectedNames) {
    try {
        # The uploaded release asset is the directory itself. Enumerate every
        # immediate entry, including hidden entries and directories, so a nested
        # payload cannot evade an ordinary -File listing. Release artifacts are
        # regular, visible files only; reparse-backed files are not accepted.
        $entries = @(Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop)
        if ($entries.Count -ne 8) { return $false }
        foreach ($entry in $entries) {
            if ($entry.PSIsContainer -or
                    ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    ($entry.Attributes -band [IO.FileAttributes]::Hidden) -ne 0) {
                return $false
            }
        }
        $actualNames = @($entries | Select-Object -ExpandProperty Name | Sort-Object)
        return ((@($actualNames) -join '|') -ceq (@($ExpectedNames | Sort-Object) -join '|'))
    } catch { return $false }
}

function Test-BuildReleaseBundle(
        [string]$BundleRoot,
        [string]$ExpectedCommit,
        [string]$ExpectedArtifactSourceCommit) {
    try {
        $root = ConvertTo-AbsoluteRepoPath $BundleRoot
        $manifestPath = Join-Path $root 'release-manifest.properties'
        $sumsPath = Join-Path $root 'SHA256SUMS'
        if (-not (Test-Path -LiteralPath $root -PathType Container) -or
                -not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
                -not (Test-Path -LiteralPath $sumsPath -PathType Leaf)) { return $false }
        $manifest = Read-PropertiesFile $manifestPath
        if ($null -eq $manifest -or [string]$manifest.schema -cne 'MCACE_RELEASE_BUNDLE_V4' -or
                [string]$manifest.bundle_profile -cne 'RELEASE' -or [string]$manifest.release_identity -cne 'true' -or
                [string]$manifest.product_version -cne '0.0.1' -or [int]$manifest.deployable_count -ne 6 -or
                [int]$manifest.bundle_entry_count -ne 8 -or
                [string]$manifest.source_commit -cne $ExpectedCommit -or
                [string]$manifest.artifact_source_commit -cne $ExpectedArtifactSourceCommit) { return $false }
        $jarNames = @('mcace-client-fabric-1.21.11.jar','mcace-client-fabric-26.1.2.jar','mcace-client-fabric-26.2.jar',
            'mcace-server-velocity.jar','mcace-server-bungeecord.jar','mcace-server-paper.jar')
        $manifestNames = @(
            'schema','bundle_profile','release_identity','deployable_count','bundle_entry_count',
            'product_version','source_commit','artifact_source_commit','root_java_version',
            'root_java_specification_version','root_gradle_version','modern_java_version',
            'modern_java_specification_version','modern_gradle_version')
        foreach ($jarName in $jarNames) {
            $key = $jarName.Remove($jarName.Length - 4).Replace('-', '_').Replace('.', '_')
            $manifestNames += "artifact.$key.file"
            $manifestNames += "artifact.$key.sha256"
            if ($jarName.StartsWith('mcace-client-fabric-', [StringComparison]::Ordinal)) {
                $manifestNames += "artifact.$key.minecraft_version"
                $manifestNames += "artifact.$key.client_build_id"
            }
        }
        if (-not (Test-ExactProperties $manifest $manifestNames)) { return $false }
        $expectedNames = @($jarNames + 'release-manifest.properties' + 'SHA256SUMS' | Sort-Object)
        if (-not (Test-ExactReleaseBundleEntrySet $root $expectedNames)) { return $false }
        $sumDoc = Read-ReleaseLockedFileBytes $sumsPath 64 1048576 'RELEASE_SHA256SUMS'
        $sumRaw = [Text.UTF8Encoding]::new($false, $true).GetString($sumDoc.bytes)
        if ($sumRaw.Contains("`r") -or -not $sumRaw.EndsWith("`n")) { return $false }
        $sumLines = @($sumRaw.TrimEnd("`n") -split "`n")
        if ($sumLines.Count -ne 6) { return $false }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($line in $sumLines) {
            $parts = ([string]$line) -split '  ', 2
            if ($parts.Count -ne 2 -or $parts[0] -cnotmatch '^[0-9a-f]{64}$' -or
                    $parts[1] -notin $jarNames -or -not $seen.Add($parts[1])) { return $false }
            $jarDoc = Read-ReleaseLockedFileBytes (Join-Path $root $parts[1]) `
                1024 134217728 'RELEASE_BUNDLE_JAR'
            if ([string]$jarDoc.sha256 -cne $parts[0]) { return $false }
            $key = $parts[1].Remove($parts[1].Length - 4).Replace('-', '_').Replace('.', '_')
            if ([string]$manifest."artifact.$key.file" -cne $parts[1] -or
                    [string]$manifest."artifact.$key.sha256" -cne $parts[0]) { return $false }
            if ($parts[1] -cmatch '^mcace-client-fabric-(?<target>1\.21\.11|26\.1\.2|26\.2)\.jar$') {
                if ([string]$manifest."artifact.$key.minecraft_version" -cne $Matches.target -or
                        [string]$manifest."artifact.$key.client_build_id" -cne
                            "fabric-$($Matches.target)-$ExpectedArtifactSourceCommit") { return $false }
            }
        }
        if ($seen.Count -ne 6) { return $false }
        $compatibilityReport = Read-StrictAbsoluteJson (Join-Path $repoRoot 'build/compatibility-contract/report.json')
        if ($null -eq $compatibilityReport) { return $false }
        Assert-CompatibilityReport $compatibilityReport $ExpectedCommit `
            $ExpectedArtifactSourceCommit $root
        return $true
    } catch { return $false }
}

function Get-ProtectedReleaseBundleArtifactBinding(
        [string]$BundleRoot,
        [string]$ExpectedCommit,
        [string]$ExpectedArtifactSourceCommit,
        [string]$ArtifactFile) {
    if (-not (Test-BuildReleaseBundle $BundleRoot $ExpectedCommit $ExpectedArtifactSourceCommit)) {
        throw 'MCACE_RELEASE_PROTECTED_BUNDLE_INVALID'
    }
    $root = ConvertTo-AbsoluteRepoPath $BundleRoot
    $manifestPath = Join-Path $root 'release-manifest.properties'
    $manifest = Read-PropertiesFile $manifestPath
    $manifestDoc = Read-ReleaseLockedFileBytes $manifestPath 64 1048576 `
        'PROTECTED_RELEASE_MANIFEST'
    $allowed = @('mcace-client-fabric-1.21.11.jar','mcace-client-fabric-26.1.2.jar',
        'mcace-client-fabric-26.2.jar','mcace-server-velocity.jar',
        'mcace-server-bungeecord.jar','mcace-server-paper.jar')
    if ($ArtifactFile -cnotin $allowed) { throw 'MCACE_RELEASE_BUNDLE_ARTIFACT_FILE_INVALID' }
    $key = $ArtifactFile.Remove($ArtifactFile.Length - 4).Replace('-', '_').Replace('.', '_')
    $artifact = Read-ReleaseLockedFileBytes (Join-Path $root $ArtifactFile) `
        1024 134217728 'PROTECTED_RELEASE_ARTIFACT'
    if ([string]$manifest."artifact.$key.file" -cne $ArtifactFile -or
            [string]$manifest."artifact.$key.sha256" -cne [string]$artifact.sha256) {
        throw 'MCACE_RELEASE_BUNDLE_ARTIFACT_MANIFEST_BINDING_INVALID'
    }
    return [pscustomobject]@{
        root=$root; file=$ArtifactFile; sha256=[string]$artifact.sha256
        size_bytes=[long]$artifact.size_bytes; source_commit=[string]$manifest.source_commit
        artifact_source_commit=[string]$manifest.artifact_source_commit
        manifest_sha256=[string]$manifestDoc.sha256
    }
}

function Test-SourceProvenance([object]$Value, [string]$Current) {
    if (-not (Test-Commit $Value) -or $Current -notmatch '^[0-9a-f]{40}$') { return $false }
    if (Test-StringEqual $Value $Current) { return $true }
    & git -C $repoRoot merge-base --is-ancestor ([string]$Value) $Current 2>$null
    if ($LASTEXITCODE -ne 0) { return $false }
    $changed = @(& git -C $repoRoot diff --name-only ("$Value..$Current") 2>$null)
    if ($LASTEXITCODE -ne 0) { return $false }
    foreach ($path in $changed) {
        $normalized = ([string]$path).Replace('\','/')
        if ($normalized -notmatch '^(README\.md|README_CN\.md|docs/evidence/.+)$') {
            return $false
        }
    }
    return $true
}

function Get-ExpectedMatrixCases {
    $list = [Collections.Generic.List[object]]::new()
    foreach ($version in @('1.21.11','26.1.2','26.2')) {
        foreach ($backend in @('PAPER','FOLIA')) {
            foreach ($proxy in @('VELOCITY','BUNGEE')) {
                $protocol = if ($version -ceq '1.21.11') { 774 } elseif ($version -ceq '26.1.2') { 775 } else { 776 }
                $java = if ($version -ceq '1.21.11') { 21 } else { 25 }
                $lane = if ($version -ceq '26.2' -and $backend -ceq 'FOLIA') { 'BETA' } else { 'STABLE' }
                $proxyId = if ($proxy -ceq 'VELOCITY') { 'velocity' } else { 'bungee' }
                $selector = if ($backend -ceq 'FOLIA') {
                    if ($proxy -ceq 'VELOCITY') {
                        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realVelocityModernForwardingToFoliaReturnsShadowContext'
                    } else {
                        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realBungeeIpForwardingToFoliaReturnsShadowContext'
                    }
                } else {
                    if ($proxy -ceq 'VELOCITY') {
                        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realVelocityModernForwardingOfflinePlayerProbeReachesMCAceChannel'
                    } else {
                        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realBungeeIpForwardingOfflinePlayerProbeReachesMCAceChannel'
                    }
                }
                [void]$list.Add([pscustomobject]@{
                    case_id="$version-$($backend.ToLowerInvariant())-$proxyId"
                    minecraft_version=$version; minecraft_protocol=$protocol
                    server_java_feature=$java; backend=$backend; proxy=$proxy
                    lane=$lane; selector=$selector
                })
            }
        }
    }
    return $list.ToArray()
}

function Assert-MatrixNativeCurrent([object]$Current, [object]$Report) {
    $currentNames = @('source_commit','product_version','target_versions','case_count','source_manifest_sha256','source_file_count',
        'wrapper_sha256','wrapper_test_sha256','runtime_assets_manifest_sha256','prepared_manifest_sha256',
        'assets','prepared_trees','root_jdk','server_jdks','gradle','product_jars','definitions')
    if (-not (Test-ExactProperties $Current $currentNames) -or
            -not (Test-StringEqual $Current.source_commit ([string]$Report.source_commit)) -or
            -not (Test-StringEqual $Current.product_version '0.0.1') -or
            -not (Test-StringEqual $Current.product_version ([string]$Report.product_version)) -or
            -not (Test-JsonArray $Current.target_versions) -or
            ((@($Current.target_versions) -join ',') -cne '1.21.11,26.1.2,26.2') -or
            -not (Test-JsonInteger $Current.case_count) -or [int]$Current.case_count -ne 12 -or
            -not (Test-JsonInteger $Current.source_file_count) -or [int]$Current.source_file_count -lt 20 -or
            -not (Test-JsonArray $Current.assets) -or @($Current.assets).Count -ne 8 -or
            -not (Test-JsonArray $Current.prepared_trees) -or @($Current.prepared_trees).Count -ne 6 -or
            -not (Test-JsonArray $Current.server_jdks) -or @($Current.server_jdks).Count -ne 2 -or
            -not (Test-JsonArray $Current.definitions) -or @($Current.definitions).Count -ne 12 -or
            -not (Test-ExactProperties $Current.product_jars @('velocity','bungee','paper'))) {
        throw 'MCACE_RELEASE_MATRIX_CURRENT_BINDING_INVALID'
    }
    foreach ($name in @('source_manifest_sha256','wrapper_sha256','wrapper_test_sha256',
            'runtime_assets_manifest_sha256','prepared_manifest_sha256')) {
        if (-not (Test-Sha256 $Current.$name)) { throw "MCACE_RELEASE_MATRIX_CURRENT_HASH_INVALID|$name" }
    }

    $assetNames = @('project','version','build','sha256','size','channel','java_major')
    $assetMap = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($asset in @($Current.assets)) {
        if (-not (Test-ExactProperties $asset $assetNames) -or
                [string]$asset.project -notin @('paper','folia','velocity','bungeecord') -or
                -not (Test-NonEmptyJsonString $asset.version) -or [string]$asset.build -cnotmatch '^[0-9]+$' -or
                -not (Test-Sha256 $asset.sha256) -or -not (Test-JsonInteger $asset.size) -or [long]$asset.size -le 0 -or
                -not (Test-JsonInteger $asset.java_major)) {
            throw 'MCACE_RELEASE_MATRIX_ASSET_INVALID'
        }
        $project = [string]$asset.project; $version = [string]$asset.version
        $key = "$project|$version"
        if ($assetMap.ContainsKey($key)) { throw 'MCACE_RELEASE_MATRIX_ASSET_DUPLICATE' }
        if ($project -in @('paper','folia')) {
            if ($version -notin @('1.21.11','26.1.2','26.2') -or
                    [int]$asset.java_major -ne $(if ($version -ceq '1.21.11') { 21 } else { 25 }) -or
                    -not (Test-StringEqual $asset.channel $(if ($project -ceq 'folia' -and $version -ceq '26.2') { 'BETA' } else { 'STABLE' }))) {
                throw 'MCACE_RELEASE_MATRIX_BACKEND_ASSET_IDENTITY_INVALID'
            }
        } elseif (($project -ceq 'velocity' -and $version -cne '3.5.1-615') -or
                ($project -ceq 'bungeecord' -and $version -cne '2085') -or
                [int]$asset.java_major -ne 21 -or -not (Test-StringEqual $asset.channel 'REVIEWED')) {
            throw 'MCACE_RELEASE_MATRIX_PROXY_ASSET_IDENTITY_INVALID'
        }
        $assetMap.Add($key, $asset)
    }
    foreach ($key in @('paper|1.21.11','paper|26.1.2','paper|26.2','folia|1.21.11',
            'folia|26.1.2','folia|26.2','velocity|3.5.1-615','bungeecord|2085')) {
        if (-not $assetMap.ContainsKey($key)) { throw "MCACE_RELEASE_MATRIX_ASSET_MISSING|$key" }
    }

    $preparedNames = @('project','version','build','server_sha256','prepared_tree_sha256','file_count','total_size')
    $preparedMap = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($prepared in @($Current.prepared_trees)) {
        if (-not (Test-ExactProperties $prepared $preparedNames) -or
                [string]$prepared.project -notin @('paper','folia') -or
                [string]$prepared.version -notin @('1.21.11','26.1.2','26.2') -or
                [string]$prepared.build -cnotmatch '^[0-9]+$' -or
                -not (Test-Sha256 $prepared.server_sha256) -or -not (Test-Sha256 $prepared.prepared_tree_sha256) -or
                -not (Test-JsonInteger $prepared.file_count) -or [int]$prepared.file_count -le 0 -or
                -not (Test-JsonInteger $prepared.total_size) -or [long]$prepared.total_size -le 0) {
            throw 'MCACE_RELEASE_MATRIX_PREPARED_TREE_INVALID'
        }
        $key = "$($prepared.project)|$($prepared.version)"
        if ($preparedMap.ContainsKey($key)) { throw 'MCACE_RELEASE_MATRIX_PREPARED_TREE_DUPLICATE' }
        $asset = $assetMap[$key]
        if (-not (Test-StringEqual $prepared.build ([string]$asset.build)) -or
                -not (Test-StringEqual $prepared.server_sha256 ([string]$asset.sha256))) {
            throw 'MCACE_RELEASE_MATRIX_PREPARED_TREE_ASSET_MISMATCH'
        }
        $preparedMap.Add($key, $prepared)
    }

    $jdkNames = @('feature','version','java_executable_sha256','java_executable_size','release_sha256',
        'modules_sha256','modules_size','jvm_sha256','jvm_size')
    $jdkMap = [Collections.Generic.Dictionary[int,object]]::new()
    foreach ($jdk in @($Current.server_jdks)) {
        if (-not (Test-ExactProperties $jdk $jdkNames) -or -not (Test-JsonInteger $jdk.feature) -or
                [int]$jdk.feature -notin @(21,25) -or -not (Test-NonEmptyJsonString $jdk.version)) {
            throw 'MCACE_RELEASE_MATRIX_JDK_INVALID'
        }
        foreach ($name in @('java_executable_sha256','release_sha256','modules_sha256','jvm_sha256')) {
            if (-not (Test-Sha256 $jdk.$name)) { throw "MCACE_RELEASE_MATRIX_JDK_HASH_INVALID|$name" }
        }
        foreach ($name in @('java_executable_size','modules_size','jvm_size')) {
            if (-not (Test-JsonInteger $jdk.$name) -or [long]$jdk.$name -le 0) { throw "MCACE_RELEASE_MATRIX_JDK_SIZE_INVALID|$name" }
        }
        if ($jdkMap.ContainsKey([int]$jdk.feature)) { throw 'MCACE_RELEASE_MATRIX_JDK_DUPLICATE' }
        $jdkMap.Add([int]$jdk.feature, $jdk)
    }
    if (-not $jdkMap.ContainsKey(21) -or -not $jdkMap.ContainsKey(25) -or
            -not (Test-ExactProperties $Current.root_jdk $jdkNames) -or
            ((($jdkNames | ForEach-Object { [string]$Current.root_jdk.$_ }) -join "`n") -cne
                (($jdkNames | ForEach-Object { [string]$jdkMap[21].$_ }) -join "`n"))) {
        throw 'MCACE_RELEASE_MATRIX_ROOT_JDK_MISMATCH'
    }

    $gradleNames = @('version','command_sha256','launcher_sha256','core_sha256','installation_manifest_sha256',
        'installation_file_count','installation_total_size')
    if (-not (Test-ExactProperties $Current.gradle $gradleNames) -or
            -not (Test-StringEqual $Current.gradle.version '9.6.1') -or
            -not (Test-JsonInteger $Current.gradle.installation_file_count) -or [int]$Current.gradle.installation_file_count -le 0 -or
            -not (Test-JsonInteger $Current.gradle.installation_total_size) -or [long]$Current.gradle.installation_total_size -le 0) {
        throw 'MCACE_RELEASE_MATRIX_GRADLE_INVALID'
    }
    foreach ($name in @('command_sha256','launcher_sha256','core_sha256','installation_manifest_sha256')) {
        if (-not (Test-Sha256 $Current.gradle.$name)) { throw "MCACE_RELEASE_MATRIX_GRADLE_HASH_INVALID|$name" }
    }

    $productJarNames = @('relative','sha256','size')
    $productRelatives = [ordered]@{
        velocity='mcace-server-velocity/build/libs/mcace-server-velocity-0.0.1.jar'
        bungee='mcace-server-bungeecord/build/libs/mcace-server-bungeecord-0.0.1.jar'
        paper='mcace-server-paper/build/libs/mcace-server-paper-0.0.1.jar'
    }
    foreach ($name in @('velocity','bungee','paper')) {
        $jar = $Current.product_jars.$name
        if (-not (Test-ExactProperties $jar $productJarNames) -or
                -not (Test-StringEqual $jar.relative $productRelatives[$name]) -or
                -not (Test-Sha256 $jar.sha256) -or -not (Test-JsonInteger $jar.size) -or [long]$jar.size -le 0) {
            throw "MCACE_RELEASE_MATRIX_PRODUCT_JAR_INVALID|$name"
        }
    }

    $definitionNames = @('case_id','minecraft_version','minecraft_protocol','server_java_feature','backend','proxy',
        'lane','selector','server_asset_identity','server_asset_sha256','prepared_tree_sha256',
        'proxy_asset_identity','proxy_asset_sha256')
    $definitionMap = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $expectedDefinitions = @(Get-ExpectedMatrixCases)
    $definitions = @($Current.definitions)
    for ($definitionIndex = 0; $definitionIndex -lt $definitions.Count; $definitionIndex++) {
        $definition = $definitions[$definitionIndex]
        $expectedDefinition = $expectedDefinitions[$definitionIndex]
        if (-not (Test-ExactProperties $definition $definitionNames) -or
                -not (Test-StringEqual $definition.case_id ([string]$expectedDefinition.case_id)) -or
                -not (Test-StringEqual $definition.minecraft_version ([string]$expectedDefinition.minecraft_version)) -or
                -not (Test-JsonInteger $definition.minecraft_protocol) -or
                [int]$definition.minecraft_protocol -ne [int]$expectedDefinition.minecraft_protocol -or
                -not (Test-JsonInteger $definition.server_java_feature) -or
                [int]$definition.server_java_feature -ne [int]$expectedDefinition.server_java_feature -or
                -not (Test-StringEqual $definition.backend ([string]$expectedDefinition.backend)) -or
                -not (Test-StringEqual $definition.proxy ([string]$expectedDefinition.proxy)) -or
                -not (Test-StringEqual $definition.lane ([string]$expectedDefinition.lane)) -or
                -not (Test-StringEqual $definition.selector ([string]$expectedDefinition.selector)) -or
                -not (Test-Sha256 $definition.server_asset_sha256) -or
                -not (Test-Sha256 $definition.prepared_tree_sha256) -or -not (Test-Sha256 $definition.proxy_asset_sha256)) {
            throw 'MCACE_RELEASE_MATRIX_DEFINITION_INVALID'
        }
        $id = [string]$definition.case_id
        if ($definitionMap.ContainsKey($id)) { throw 'MCACE_RELEASE_MATRIX_DEFINITION_DUPLICATE' }
        $definitionMap.Add($id, $definition)
    }

    foreach ($case in @($Report.cases)) {
        $id = [string]$case.case_id
        if (-not $definitionMap.ContainsKey($id)) { throw "MCACE_RELEASE_MATRIX_CASE_DEFINITION_MISSING|$id" }
        $definition = $definitionMap[$id]
        foreach ($name in @('minecraft_version','minecraft_protocol','server_java_feature','backend','proxy','lane',
                'selector','server_asset_identity','proxy_asset_identity')) {
            if ([string]$case.$name -cne [string]$definition.$name) {
                throw "MCACE_RELEASE_MATRIX_CASE_DEFINITION_MISMATCH|$id|$name"
            }
        }
        $backendKey = "$(([string]$case.backend).ToLowerInvariant())|$($case.minecraft_version)"
        $proxyProject = if ([string]$case.proxy -ceq 'VELOCITY') { 'velocity' } else { 'bungeecord' }
        $proxyVersion = if ($proxyProject -ceq 'velocity') { '3.5.1-615' } else { '2085' }
        $backendAsset = $assetMap[$backendKey]
        $proxyAsset = $assetMap["$proxyProject|$proxyVersion"]
        $prepared = $preparedMap[$backendKey]
        $proxyProduct = if ($proxyProject -ceq 'velocity') { $Current.product_jars.velocity } else { $Current.product_jars.bungee }
        if (-not (Test-StringEqual $definition.server_asset_identity "$($backendAsset.project):$($backendAsset.version):$($backendAsset.build)") -or
                -not (Test-StringEqual $definition.server_asset_sha256 ([string]$backendAsset.sha256)) -or
                -not (Test-StringEqual $definition.prepared_tree_sha256 ([string]$prepared.prepared_tree_sha256)) -or
                -not (Test-StringEqual $definition.proxy_asset_identity "$($proxyAsset.project):$($proxyAsset.version):$($proxyAsset.build)") -or
                -not (Test-StringEqual $definition.proxy_asset_sha256 ([string]$proxyAsset.sha256)) -or
                -not (Test-StringEqual $case.run_root.backend_jar_sha256 ([string]$backendAsset.sha256)) -or
                [long]$case.run_root.backend_jar_size -ne [long]$backendAsset.size -or
                -not (Test-StringEqual $case.run_root.proxy_jar_sha256 ([string]$proxyAsset.sha256)) -or
                [long]$case.run_root.proxy_jar_size -ne [long]$proxyAsset.size -or
                -not (Test-StringEqual $case.run_root.prepared_tree_sha256 ([string]$prepared.prepared_tree_sha256)) -or
                [int]$case.run_root.prepared_file_count -ne [int]$prepared.file_count -or
                [long]$case.run_root.prepared_total_size -ne [long]$prepared.total_size -or
                -not (Test-StringEqual $case.run_root.proxy_plugin_sha256 ([string]$proxyProduct.sha256)) -or
                [long]$case.run_root.proxy_plugin_size -ne [long]$proxyProduct.size -or
                -not (Test-StringEqual $case.run_root.backend_plugin_sha256 ([string]$Current.product_jars.paper.sha256)) -or
                [long]$case.run_root.backend_plugin_size -ne [long]$Current.product_jars.paper.size) {
            throw "MCACE_RELEASE_MATRIX_CASE_NATIVE_CROSS_BINDING_INVALID|$id"
        }
    }
}

function Test-MatrixCanonicalRelativePath([object]$Value) {
    if ($Value -isnot [string]) { return $false }
    $text = [string]$Value
    return -not [string]::IsNullOrWhiteSpace($text) -and
        $text.IndexOf('\') -lt 0 -and
        -not $text.StartsWith('/', [StringComparison]::Ordinal) -and
        $text -cnotmatch '^[A-Za-z]:' -and $text.IndexOf('//') -lt 0 -and
        $text -cnotmatch '(^|/)\.{1,2}($|/)' -and $text -ceq $text.Normalize()
}

function Assert-MatrixNoSyntheticMarkers([object]$Value, [string]$Role) {
    if ($null -eq $Value -or $Value -is [ValueType]) { return }
    if ($Value -is [string]) {
        if ([string]$Value -match '(?i)(?:^|[^a-z0-9])(synthetic|test[_-]?fixture|manual[_-]?byte[_-]?array)(?:$|[^a-z0-9])') {
            throw "MCACE_RELEASE_MATRIX_SYNTHETIC_EVIDENCE_REJECTED|$Role"
        }
        return
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        foreach ($property in @($Value.PSObject.Properties)) {
            if ([string]$property.Name -match '(?i)^test[_-]?fixture$') {
                if ($property.Value -isnot [bool] -or [bool]$property.Value) {
                    throw "MCACE_RELEASE_MATRIX_SYNTHETIC_EVIDENCE_REJECTED|$Role"
                }
                continue
            }
            if ([string]$property.Name -match '(?i)synthetic|manual[_-]?byte[_-]?array') {
                throw "MCACE_RELEASE_MATRIX_SYNTHETIC_EVIDENCE_REJECTED|$Role"
            }
            Assert-MatrixNoSyntheticMarkers $property.Value $Role
        }
        return
    }
    if ($Value -is [Collections.IDictionary]) {
        foreach ($key in @($Value.Keys)) { Assert-MatrixNoSyntheticMarkers $Value[$key] $Role }
        return
    }
    if ($Value -is [Collections.IEnumerable]) {
        foreach ($item in $Value) { Assert-MatrixNoSyntheticMarkers $item $Role }
    }
}

function Read-MatrixLockedFileBytes([string]$Path, [string]$Role) {
    $absolute = [IO.Path]::GetFullPath($Path)
    Assert-ReleasePathChainNoReparse $absolute $true
    if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) {
        throw "MCACE_RELEASE_MATRIX_FILE_REQUIRED|$Role"
    }
    $before = Get-ReleaseNoFollowFileIdentity $absolute
    $stream = New-Object IO.FileStream(
        $absolute, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        $length = [long]$stream.Length
        if ($length -lt 3 -or $length -gt 2097152 -or $length -gt [int]::MaxValue) {
            throw "MCACE_RELEASE_MATRIX_FILE_SIZE_INVALID|$Role"
        }
        if (Test-ReleaseWindowsPlatform) {
            try { $handleIdentity = [MCAceReleaseReadinessFileIdentityV3]::FromHandle($stream.SafeFileHandle) }
            catch { throw "MCACE_RELEASE_MATRIX_HANDLE_IDENTITY_FAILED|$Role|$($_.Exception.Message)" }
            if ($handleIdentity -cne $before) {
                throw "MCACE_RELEASE_MATRIX_HANDLE_IDENTITY_CHANGED|$Role"
            }
        }
        $first = New-Object byte[] ([int]$length)
        $offset = 0
        while ($offset -lt $first.Length) {
            $read = $stream.Read($first, $offset, $first.Length - $offset)
            if ($read -le 0) { throw "MCACE_RELEASE_MATRIX_SHORT_READ|$Role|first" }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1 -or [long]$stream.Length -ne $length) {
            throw "MCACE_RELEASE_MATRIX_FILE_CHANGED_DURING_READ|$Role"
        }
        $stream.Position = 0
        $second = New-Object byte[] ([int]$length)
        $offset = 0
        while ($offset -lt $second.Length) {
            $read = $stream.Read($second, $offset, $second.Length - $offset)
            if ($read -le 0) { throw "MCACE_RELEASE_MATRIX_SHORT_READ|$Role|second" }
            $offset += $read
        }
        $firstHash = Get-BytesSha256 $first
        if ((Get-BytesSha256 $second) -cne $firstHash) {
            throw "MCACE_RELEASE_MATRIX_LOCKED_DOUBLE_READ_MISMATCH|$Role"
        }
    } finally { $stream.Dispose() }
    Assert-ReleasePathChainNoReparse $absolute $true
    if ((Get-ReleaseNoFollowFileIdentity $absolute) -cne $before) {
        throw "MCACE_RELEASE_MATRIX_PATH_IDENTITY_CHANGED|$Role"
    }
    return [pscustomobject]@{
        absolute=$absolute; bytes=$first; size=[long]$first.Length
        size_bytes=[long]$first.Length; sha256=$firstHash
    }
}

function Assert-MatrixEvidencePackageDirectory([string]$Prefix, [string[]]$ExpectedRawFiles) {
    if ([string]::IsNullOrWhiteSpace($Prefix) -or $Prefix.Contains('\') -or
            $Prefix.StartsWith('/') -or $Prefix.Contains(':') -or
            -not $Prefix.StartsWith(($evidenceRootRelative + '/'), [StringComparison]::Ordinal)) {
        throw 'MCACE_RELEASE_MATRIX_PACKAGE_PATH_INVALID'
    }
    $segments = @($Prefix.Split('/'))
    if (@($segments | Where-Object { $_ -in @('', '.', '..') }).Count -ne 0) {
        throw 'MCACE_RELEASE_MATRIX_PACKAGE_PATH_ESCAPE_REJECTED'
    }
    $absolute = [IO.Path]::GetFullPath((Join-Path $repoRoot $Prefix))
    $rootPrefix = $repoRoot.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    if (-not $absolute.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $absolute -PathType Container)) {
        throw 'MCACE_RELEASE_MATRIX_PACKAGE_REQUIRED'
    }
    Assert-ReleasePathChainNoReparse $absolute $true
    $null = Get-ReleaseNoFollowFileIdentity $absolute -Directory
    $rootChildren = @(Get-ChildItem -LiteralPath $absolute -Force -ErrorAction Stop)
    $expectedRootNames = @('report.json','binding.json','commit.json','raw-manifest.json',
        'supervisor-signing-request.json','supervisor-receipt.json','raw')
    $actualRootNames = @($rootChildren | ForEach-Object Name | Sort-Object)
    if ($actualRootNames.Count -ne $expectedRootNames.Count -or
            (($actualRootNames -join "`n") -cne (($expectedRootNames | Sort-Object) -join "`n"))) {
        throw 'MCACE_RELEASE_MATRIX_PACKAGE_FILE_SET_INVALID'
    }
    foreach ($child in $rootChildren) {
        if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'MCACE_RELEASE_MATRIX_PACKAGE_REPARSE_ENTRY_REJECTED'
        }
        if ($child.Name -ceq 'raw') {
            if (-not $child.PSIsContainer) { throw 'MCACE_RELEASE_MATRIX_RAW_DIRECTORY_REQUIRED' }
            $null = Get-ReleaseNoFollowFileIdentity $child.FullName -Directory
        } else {
            if ($child.PSIsContainer) { throw 'MCACE_RELEASE_MATRIX_REGULAR_FILE_REQUIRED' }
            $null = Get-ReleaseNoFollowFileIdentity $child.FullName
        }
    }
    $rawRoot = Join-Path $absolute 'raw'
    $rawChildren = @(Get-ChildItem -LiteralPath $rawRoot -Force -ErrorAction Stop)
    if (@($rawChildren | Where-Object {
                $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
            }).Count -ne 0) {
        throw 'MCACE_RELEASE_MATRIX_RAW_REGULAR_FILES_REQUIRED'
    }
    foreach ($child in $rawChildren) { $null = Get-ReleaseNoFollowFileIdentity $child.FullName }
    $actualRawNames = @($rawChildren | ForEach-Object Name | Sort-Object)
    $wantedRawNames = @($ExpectedRawFiles | Sort-Object)
    if ($actualRawNames.Count -ne 12 -or $wantedRawNames.Count -ne 12 -or
            (($actualRawNames -join "`n") -cne ($wantedRawNames -join "`n"))) {
        throw 'MCACE_RELEASE_MATRIX_EXACT_12_RAW_FILES_REQUIRED'
    }
}

function Get-MatrixOrderedRawReportSetSha256([object[]]$Descriptors, [string]$SourceCommit) {
    $records = @($Descriptors | ForEach-Object {
        [pscustomobject][ordered]@{
            ordinal=[int]$_.ordinal; case_id=[string]$_.case_id; path=[string]$_.path
            sha256=[string]$_.sha256; size_bytes=[long]$_.size_bytes
        }
    })
    return Get-CompactObjectSha256 ([pscustomobject][ordered]@{
        domain='MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_SET_V1'
        source_commit=$SourceCommit
        reports=$records
    })
}

function Assert-MatrixRawReport([object]$Raw, [object]$Case, [object]$Expected) {
    $names = @('schema','proxy','backend_platform','backend_minecraft_version','forwarding_mode',
        'forwarding_configured','proxy_port','backend_port','tcp_connected','login_success',
        'compression_seen','configuration_finished','mcace_server_hello','mcace_auth_result',
        'mcace_auth_accepted','backend_admission','backend_context_shadow_audit','channels',
        'packet_trace','limitations','cleanup_process_ids','remaining_run_processes')
    $forwarding = if ([string]$Expected.proxy -ceq 'VELOCITY') { 'velocity-modern' } else { 'bungee-ip-forwarding' }
    if (-not (Test-ExactProperties $Raw $names) -or
            -not (Test-JsonInteger $Raw.schema) -or [int]$Raw.schema -ne 4 -or
            -not (Test-StringEqual $Raw.proxy ([string]$Expected.proxy)) -or
            -not (Test-StringEqual $Raw.backend_platform ([string]$Expected.backend)) -or
            -not (Test-StringEqual $Raw.backend_minecraft_version ([string]$Expected.minecraft_version)) -or
            -not (Test-StringEqual $Raw.forwarding_mode $forwarding) -or
            -not (Test-JsonInteger $Raw.proxy_port) -or [int]$Raw.proxy_port -lt 1 -or
            [int]$Raw.proxy_port -gt 65535 -or -not (Test-JsonInteger $Raw.backend_port) -or
            [int]$Raw.backend_port -lt 1 -or [int]$Raw.backend_port -gt 65535 -or
            [int]$Raw.proxy_port -eq [int]$Raw.backend_port) {
        throw "MCACE_RELEASE_MATRIX_RAW_IDENTITY_INVALID|$($Expected.case_id)"
    }
    foreach ($name in @('forwarding_configured','tcp_connected','login_success','compression_seen',
            'configuration_finished','mcace_server_hello','mcace_auth_result','mcace_auth_accepted',
            'backend_admission','backend_context_shadow_audit')) {
        if (-not (Test-True $Raw.$name)) {
            throw "MCACE_RELEASE_MATRIX_RAW_ASSERTION_FAILED|$($Expected.case_id)|$name"
        }
    }
    $cleanupIds = @($Raw.cleanup_process_ids)
    if (@($Raw.limitations).Count -ne 0 -or @($Raw.remaining_run_processes).Count -ne 0 -or
            $cleanupIds.Count -lt 2 -or @($cleanupIds | Where-Object {
                -not (Test-JsonInteger $_) -or [long]$_ -le 0
            }).Count -ne 0 -or @($cleanupIds | Select-Object -Unique).Count -ne $cleanupIds.Count -or
            $cleanupIds.Count -ne [int]$Case.cleanup_process_count) {
        throw "MCACE_RELEASE_MATRIX_RAW_CLEANUP_INVALID|$($Expected.case_id)"
    }
    $playId = if ([string]$Expected.minecraft_version -ceq '1.21.11') { '0x30' } else { '0x31' }
    if (@($Raw.channels | Where-Object { [string]$_ -ceq 'mcace:handshake' }).Count -lt 1 -or
            @($Raw.packet_trace | Where-Object { [string]$_ -ceq "PLAY:$playId" }).Count -ne 1) {
        throw "MCACE_RELEASE_MATRIX_RAW_PROTOCOL_INVALID|$($Expected.case_id)"
    }
}

function Read-MatrixJsonDescriptor(
        [object]$Descriptor,
        [string]$StoredPath,
        [string]$RepoPath,
        [string]$Prefix) {
    # Matrix publisher paths are canonical relative to docs/evidence. Bind that
    # namespace to a tracked repository path, then perform a no-follow identity
    # check plus an exclusive same-handle double read.
    if (-not (Test-ExactProperties $Descriptor @('path','sha256','size_bytes')) -or
            -not (Test-StringEqual $Descriptor.path $StoredPath) -or
            -not (Test-Sha256 $Descriptor.sha256) -or
            -not (Test-JsonInteger $Descriptor.size_bytes) -or [long]$Descriptor.size_bytes -le 0) {
        throw 'MCACE_RELEASE_MATRIX_EVIDENCE_DESCRIPTOR_INVALID'
    }
    $absolute = Assert-CanonicalRepoRelativePath $RepoPath $Prefix (@($RepoPath.Split('/'))[-1])
    $artifact = Read-MatrixLockedFileBytes $absolute "descriptor:$StoredPath"
    if ([string]$artifact.sha256 -cne [string]$Descriptor.sha256 -or
            [long]$artifact.size_bytes -ne [long]$Descriptor.size_bytes) {
        throw 'MCACE_RELEASE_MATRIX_EVIDENCE_DESCRIPTOR_HASH_OR_SIZE_MISMATCH'
    }
    if ($artifact.bytes.Length -ge 3 -and $artifact.bytes[0] -eq 0xEF -and
            $artifact.bytes[1] -eq 0xBB -and $artifact.bytes[2] -eq 0xBF) {
        throw 'MCACE_RELEASE_MATRIX_JSON_UTF8_BOM_REJECTED'
    }
    $raw = [Text.UTF8Encoding]::new($false, $true).GetString($artifact.bytes)
    $value = ConvertFrom-StrictJsonRaw $raw
    Assert-MatrixNoSyntheticMarkers $value $StoredPath
    return [pscustomobject]@{
        relative=$RepoPath; absolute=$absolute; bytes=$artifact.bytes
        size=$artifact.size_bytes; size_bytes=$artifact.size_bytes; sha256=$artifact.sha256
        raw=$raw; value=$value
    }
}

function Get-MatrixSetSha256([string]$Domain, [object]$Value) {
    # Matrix set commitments are a cross-process contract shared with the
    # producer, external supervisor signer, and publisher.  Those components
    # hash compact UTF-8 JSON at depth 30 *without* a trailing newline.  Keep
    # Get-CompactObjectSha256 (newline-terminated) for file/object hashes, but
    # use the commitment encoding here so a genuine published package is
    # accepted by readiness instead of failing commitment binding.
    $json = ([pscustomobject][ordered]@{
        domain=$Domain; value=$Value
    } | ConvertTo-Json -Depth 30 -Compress)
    return Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($json))
}

function Test-MatrixFullPathBelow([string]$Root, [string]$Candidate) {
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([char[]]@('\','/')) +
        [IO.Path]::DirectorySeparatorChar
    $candidateFull = [IO.Path]::GetFullPath($Candidate)
    $comparison = if (Test-ReleaseWindowsPlatform) {
        [StringComparison]::OrdinalIgnoreCase
    } else { [StringComparison]::Ordinal }
    return $candidateFull.StartsWith($rootFull, $comparison)
}

function Get-MatrixApprovedSupervisorPin {
    $pin = [Environment]::GetEnvironmentVariable(
        'MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256', 'Process')
    if ([string]::IsNullOrWhiteSpace($pin) -or $pin -cnotmatch '^[0-9a-fA-F]{64}$') {
        throw 'MCACE_RELEASE_MATRIX_APPROVED_SUPERVISOR_PIN_REQUIRED'
    }
    if ($ExpectedMatrixSupervisorTrustRootSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
            $pin.ToLowerInvariant() -cne
                $ExpectedMatrixSupervisorTrustRootSha256.ToLowerInvariant()) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_PIN_NOT_APPROVED'
    }
    return $pin.ToLowerInvariant()
}

function Read-MatrixSupervisorTrustRootEvidence([string]$PackageRoot) {
    $approvedPin = Get-MatrixApprovedSupervisorPin
    if ([string]::IsNullOrWhiteSpace($MatrixSupervisorTrustRootPath)) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_TRUST_ROOT_REQUIRED'
    }
    $path = [IO.Path]::GetFullPath($MatrixSupervisorTrustRootPath)
    if (Test-MatrixFullPathBelow $repoRoot $path) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_TRUST_ROOT_MUST_BE_OUT_OF_REPO'
    }
    foreach ($forbiddenRoot in @($PackageRoot,(ConvertTo-AbsoluteRepoPath $ReleaseBundleRoot))) {
        if (-not [string]::IsNullOrWhiteSpace([string]$forbiddenRoot) -and
                (Test-MatrixFullPathBelow ([IO.Path]::GetFullPath([string]$forbiddenRoot)) $path)) {
            throw 'MCACE_RELEASE_MATRIX_SELF_SUPERVISOR_TRUST_ROOT_REJECTED'
        }
    }
    $artifact = Read-MatrixLockedFileBytes $path 'supervisor-trust-root'
    if ($artifact.bytes.Length -ge 3 -and $artifact.bytes[0] -eq 0xEF -and
            $artifact.bytes[1] -eq 0xBB -and $artifact.bytes[2] -eq 0xBF) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_TRUST_ROOT_UTF8_BOM_REJECTED'
    }
    if ([string]$artifact.sha256 -cne $approvedPin -or
            [string]$artifact.sha256 -cne
                $ExpectedMatrixSupervisorTrustRootSha256.ToLowerInvariant()) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_TRUST_ROOT_PIN_MISMATCH'
    }
    $raw = [Text.UTF8Encoding]::new($false, $true).GetString($artifact.bytes)
    $root = ConvertFrom-StrictJsonRaw $raw
    if (-not (Test-ExactProperties $root @(
            'schema','artifact_class','key_id','algorithm','modulus_base64',
            'exponent_base64','test_fixture')) -or
            -not (Test-StringEqual $root.schema 'MCACE_SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_V1') -or
            -not (Test-StringEqual $root.artifact_class 'OUT_OF_BAND_PINNED_MATRIX_SUPERVISOR_TRUST_ROOT') -or
            [string]$root.key_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$' -or
            -not (Test-StringEqual $root.algorithm 'RSA_PKCS1_SHA256') -or
            $root.test_fixture -isnot [bool] -or [bool]$root.test_fixture) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_TRUST_ROOT_INVALID'
    }
    try {
        $modulus = [Convert]::FromBase64String([string]$root.modulus_base64)
        $exponent = [Convert]::FromBase64String([string]$root.exponent_base64)
    } catch { throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_TRUST_ROOT_KEY_ENCODING_INVALID' }
    if ($modulus.Length -lt 256 -or $modulus.Length -gt 512 -or
            $exponent.Length -lt 1 -or $exponent.Length -gt 4) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_TRUST_ROOT_KEY_SIZE_INVALID'
    }
    return [pscustomobject]@{
        path=$path; document=$artifact; value=$root; modulus=$modulus; exponent=$exponent
    }
}

$matrixSupervisorReceiptPropertyNames = @(
    'schema','artifact_class','source_mode','signed_at','expires_at',
    'release_source_commit','artifact_source_commit','product_version',
    'operation_attempt_id','challenge_nonce','challenge_issued_at',
    'report_sha256','report_size_bytes','binding_sha256','binding_size_bytes',
    'raw_manifest_sha256','raw_manifest_size_bytes','ordered_raw_report_set_sha256',
    'case_runtime_commitment_sha256','case_count','process_identity_count',
    'release_bundle_schema','release_bundle_manifest_sha256',
    'release_bundle_manifest_size_bytes','release_bundle_sha256s_sha256',
    'release_bundle_sha256s_size_bytes','release_bundle_artifact_set_sha256',
    'release_bundle_artifact_count','matrix_product_jar_set_sha256',
    'matrix_product_jar_count','supervisor_independent','signer_key_id',
    'signer_trust_root_sha256','signature_algorithm','test_fixture','signature_base64')

function Get-MatrixSupervisorReceiptSigningPayload([object]$Receipt) {
    $lines = [Collections.Generic.List[string]]::new()
    [void]$lines.Add('MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_RECEIPT_SIGNING_V1')
    foreach ($name in @($matrixSupervisorReceiptPropertyNames |
            Where-Object { $_ -cne 'signature_base64' })) {
        $value = $Receipt.$name
        if ($value -is [bool]) {
            $rendered = if ([bool]$value) { 'true' } else { 'false' }
        } elseif (Test-JsonInteger $value) {
            $rendered = [Convert]::ToString(
                $value, [Globalization.CultureInfo]::InvariantCulture)
        } else { $rendered = [string]$value }
        if ($rendered -match '[\r\n]' -or $name -match '[\r\n=]') {
            throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_SIGNING_VALUE_INVALID'
        }
        [void]$lines.Add("$name=$rendered")
    }
    return [Text.UTF8Encoding]::new($false).GetBytes(($lines -join "`n") + "`n")
}

function Test-MatrixRsaPkcs1Sha256Signature(
        [byte[]]$Payload,
        [byte[]]$Signature,
        [byte[]]$Modulus,
        [byte[]]$Exponent) {
    $rsa = [Security.Cryptography.RSACryptoServiceProvider]::new()
    try {
        $rsa.PersistKeyInCsp = $false
        $rsa.ImportParameters([Security.Cryptography.RSAParameters]@{
            Modulus=$Modulus; Exponent=$Exponent
        })
        return $rsa.VerifyData($Payload, 'SHA256', $Signature)
    } finally { $rsa.Dispose() }
}

function Get-MatrixCaseRuntimeCommitment([object]$Report, [object[]]$RawDocuments) {
    if ($RawDocuments.Count -ne 12) {
        throw 'MCACE_RELEASE_MATRIX_CASE_RUNTIME_DOCUMENT_SET_INVALID'
    }
    $commitments = [Collections.Generic.List[object]]::new()
    $processCount = 0
    for ($caseIndex=0; $caseIndex -lt 12; $caseIndex++) {
        $case = @($Report.cases)[$caseIndex]
        $raw = $RawDocuments[$caseIndex]
        $processes = [Collections.Generic.List[object]]::new()
        $cleanupIds = @($raw.cleanup_process_ids)
        for ($processIndex=0; $processIndex -lt $cleanupIds.Count; $processIndex++) {
            $role = if ($processIndex -eq 0) { 'PROXY' } elseif ($processIndex -eq 1) {
                'BACKEND'
            } else { "AUXILIARY_$($processIndex - 1)" }
            $identityBody = [pscustomobject][ordered]@{
                case_id=[string]$case.case_id; role=$role
                process_id=[long]$cleanupIds[$processIndex]
                invocation_started_at=[string]$case.invocation_started_at
                invocation_finished_at=[string]$case.invocation_finished_at
                proxy_jar_sha256=[string]$case.run_root.proxy_jar_sha256
                backend_jar_sha256=[string]$case.run_root.backend_jar_sha256
            }
            [void]$processes.Add([pscustomobject][ordered]@{
                role=$role; process_id=[long]$cleanupIds[$processIndex]
                process_incarnation_sha256=Get-MatrixSetSha256 `
                    'MCACE_SERVER_VERSION_PROCESS_MATRIX_PROCESS_INCARNATION_V1' $identityBody
                cleanup_observed=$true; remaining_process_count=0
            })
            $processCount++
        }
        [void]$commitments.Add([pscustomobject][ordered]@{
            ordinal=$caseIndex + 1; case_id=[string]$case.case_id
            invocation_started_at=[string]$case.invocation_started_at
            invocation_finished_at=[string]$case.invocation_finished_at
            invocation_log_sha256=[string]$case.invocation_log_sha256
            raw_report_sha256=[string]$case.raw_report_sha256
            raw_report_size_bytes=[long]$case.raw_report_size
            cleanup_process_count=[int]$case.cleanup_process_count
            remaining_process_count=0; process_cleanup_observed=$true
            processes=$processes.ToArray()
        })
    }
    $values = $commitments.ToArray()
    return [pscustomobject]@{
        values=$values; count=12; process_count=$processCount
        sha256=Get-MatrixSetSha256 `
            'MCACE_SERVER_VERSION_PROCESS_MATRIX_CASE_RUNTIME_SET_V1' $values
    }
}

function Get-MatrixReleaseArtifactCommitment([object[]]$Artifacts) {
    $values = @($Artifacts | Sort-Object file | ForEach-Object {
        [pscustomobject][ordered]@{
            file=[string]$_.file; sha256=[string]$_.sha256; size_bytes=[long]$_.size_bytes
        }
    })
    return [pscustomobject]@{
        values=$values; count=$values.Count
        sha256=Get-MatrixSetSha256 `
            'MCACE_SERVER_VERSION_PROCESS_MATRIX_RELEASE_ARTIFACT_SET_V1' $values
    }
}

function Get-MatrixProductJarCommitment([object[]]$Bindings) {
    $values = @($Bindings | ForEach-Object {
        [pscustomobject][ordered]@{
            role=[string]$_.role; bundle_file=[string]$_.bundle_file
            matrix_relative=[string]$_.matrix_relative; sha256=[string]$_.sha256
            size_bytes=[long]$_.size_bytes
        }
    })
    return [pscustomobject]@{
        values=$values; count=$values.Count
        sha256=Get-MatrixSetSha256 `
            'MCACE_SERVER_VERSION_PROCESS_MATRIX_PRODUCT_JAR_SET_V1' $values
    }
}

function Assert-MatrixSupervisorSigningRequest(
        [object]$Document,
        [object]$ReportDocument,
        [object]$BindingDocument,
        [object]$RawManifestDocument,
        [object]$Report,
        [object]$Index,
        [object]$CaseCommitment,
        [object]$ReleaseCommitment,
        [object]$ProductCommitment,
        [object]$TrustRoot) {
    $request = $Document.value
    $names = @(
        'schema','generated_at','source_mode','release_source_commit','artifact_source_commit',
        'product_version','operation_attempt_id','challenge_nonce','challenge_issued_at',
        'receipt_not_after','report_sha256','report_size_bytes','binding_sha256',
        'binding_size_bytes','raw_manifest_sha256','raw_manifest_size_bytes',
        'ordered_raw_report_set_sha256','case_runtime_commitment_sha256','case_count',
        'process_identity_count','case_runtime_commitments','release_bundle_schema',
        'release_bundle_manifest_sha256','release_bundle_manifest_size_bytes',
        'release_bundle_sha256s_sha256','release_bundle_sha256s_size_bytes',
        'release_bundle_artifact_set_sha256','release_bundle_artifact_count',
        'release_bundle_artifacts','matrix_product_jar_set_sha256','matrix_product_jar_count',
        'matrix_product_jars','supervisor_trust_root_sha256','supervisor_signer_key_id',
        'signature_algorithm')
    if (-not (Test-ExactProperties $request $names) -or
            -not (Test-StringEqual $request.schema 'MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_SIGNING_REQUEST_V1') -or
            -not (Test-StringEqual $request.source_mode 'EXECUTED_AWAITING_EXTERNAL_SUPERVISOR') -or
            -not (Test-StringEqual $request.release_source_commit ([string]$Index.release_bundle.source_commit)) -or
            -not (Test-StringEqual $request.artifact_source_commit ([string]$Index.artifact_source_commit)) -or
            -not (Test-StringEqual $request.product_version '0.0.1') -or
            [string]$request.operation_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$request.challenge_nonce -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-StringEqual $request.report_sha256 ([string]$ReportDocument.sha256)) -or
            [long]$request.report_size_bytes -ne [long]$ReportDocument.size_bytes -or
            -not (Test-StringEqual $request.binding_sha256 ([string]$BindingDocument.sha256)) -or
            [long]$request.binding_size_bytes -ne [long]$BindingDocument.size_bytes -or
            -not (Test-StringEqual $request.raw_manifest_sha256 ([string]$RawManifestDocument.sha256)) -or
            [long]$request.raw_manifest_size_bytes -ne [long]$RawManifestDocument.size_bytes -or
            -not (Test-StringEqual $request.ordered_raw_report_set_sha256 ([string]$Report.ordered_raw_report_set_sha256)) -or
            -not (Test-StringEqual $request.case_runtime_commitment_sha256 ([string]$CaseCommitment.sha256)) -or
            [int]$request.case_count -ne 12 -or
            [int]$request.process_identity_count -ne [int]$CaseCommitment.process_count -or
            -not (Test-StringEqual $request.release_bundle_schema 'MCACE_RELEASE_BUNDLE_V4') -or
            -not (Test-StringEqual $request.release_bundle_manifest_sha256 ([string]$Index.release_bundle.manifest_sha256)) -or
            [long]$request.release_bundle_manifest_size_bytes -ne [long]$Index.release_bundle.manifest_size_bytes -or
            -not (Test-StringEqual $request.release_bundle_sha256s_sha256 ([string]$Index.release_bundle.sha256sums_sha256)) -or
            [long]$request.release_bundle_sha256s_size_bytes -ne [long]$Index.release_bundle.sha256sums_size_bytes -or
            -not (Test-StringEqual $request.release_bundle_artifact_set_sha256 ([string]$ReleaseCommitment.sha256)) -or
            [int]$request.release_bundle_artifact_count -ne 6 -or
            -not (Test-StringEqual $request.matrix_product_jar_set_sha256 ([string]$ProductCommitment.sha256)) -or
            [int]$request.matrix_product_jar_count -ne 3 -or
            -not (Test-StringEqual $request.supervisor_trust_root_sha256 ([string]$TrustRoot.document.sha256)) -or
            -not (Test-StringEqual $request.supervisor_signer_key_id ([string]$TrustRoot.value.key_id)) -or
            -not (Test-StringEqual $request.signature_algorithm 'RSA_PKCS1_SHA256')) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_SIGNING_REQUEST_INVALID'
    }
    foreach ($pair in @(
            [pscustomobject]@{ actual=$request.case_runtime_commitments; expected=$CaseCommitment.values; domain='MCACE_SERVER_VERSION_PROCESS_MATRIX_CASE_RUNTIME_SET_V1' },
            [pscustomobject]@{ actual=$request.release_bundle_artifacts; expected=$ReleaseCommitment.values; domain='MCACE_SERVER_VERSION_PROCESS_MATRIX_RELEASE_ARTIFACT_SET_V1' },
            [pscustomobject]@{ actual=$request.matrix_product_jars; expected=$ProductCommitment.values; domain='MCACE_SERVER_VERSION_PROCESS_MATRIX_PRODUCT_JAR_SET_V1' })) {
        if (-not (Test-JsonArray $pair.actual) -or
                (Get-MatrixSetSha256 ([string]$pair.domain) @($pair.actual)) -cne
                    (Get-MatrixSetSha256 ([string]$pair.domain) @($pair.expected))) {
            throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_SIGNING_REQUEST_SET_INVALID'
        }
    }
    $generated = ConvertTo-EvidenceTime $request.generated_at
    $issued = ConvertTo-EvidenceTime $request.challenge_issued_at
    $expires = ConvertTo-EvidenceTime $request.receipt_not_after
    if ($generated.UtcDateTime.Ticks -ne $issued.UtcDateTime.Ticks -or
            $issued -lt (ConvertTo-EvidenceTime $Report.generated_at) -or
            $expires -le $issued -or ($expires - $issued).TotalMinutes -gt 30) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_SIGNING_REQUEST_TIME_INVALID'
    }
    return [pscustomobject]@{ value=$request; issued_at=$issued; expires_at=$expires }
}

function Assert-MatrixSupervisorReceipt(
        [object]$Document,
        [object]$RequestValidation,
        [object]$TrustRoot) {
    $receipt = $Document.value
    if (-not (Test-ExactProperties $receipt $matrixSupervisorReceiptPropertyNames)) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_SCHEMA_INVALID'
    }
    foreach ($name in @('report_size_bytes','binding_size_bytes','raw_manifest_size_bytes',
            'case_count','process_identity_count','release_bundle_manifest_size_bytes',
            'release_bundle_sha256s_size_bytes','release_bundle_artifact_count',
            'matrix_product_jar_count')) {
        if (-not (Test-JsonInteger $receipt.$name)) {
            throw "MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_INTEGER_INVALID|$name"
        }
    }
    foreach ($name in @('supervisor_independent','test_fixture')) {
        if ($receipt.$name -isnot [bool]) {
            throw "MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_BOOLEAN_INVALID|$name"
        }
    }
    if (-not (Test-StringEqual $receipt.schema 'MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_RECEIPT_V1') -or
            -not (Test-StringEqual $receipt.artifact_class 'EXTERNALLY_SIGNED_MATRIX_SUPERVISOR_RECEIPT') -or
            -not (Test-StringEqual $receipt.source_mode 'EXTERNAL_MATRIX_SUPERVISOR') -or
            -not [bool]$receipt.supervisor_independent -or [bool]$receipt.test_fixture -or
            -not (Test-StringEqual $receipt.signer_key_id ([string]$TrustRoot.value.key_id)) -or
            -not (Test-StringEqual $receipt.signer_trust_root_sha256 ([string]$TrustRoot.document.sha256)) -or
            -not (Test-StringEqual $receipt.signature_algorithm 'RSA_PKCS1_SHA256')) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_PROVENANCE_INVALID'
    }
    $request = $RequestValidation.value
    $fieldMap = [ordered]@{
        release_source_commit='release_source_commit'; artifact_source_commit='artifact_source_commit'
        product_version='product_version'; operation_attempt_id='operation_attempt_id'
        challenge_nonce='challenge_nonce'; challenge_issued_at='challenge_issued_at'
        report_sha256='report_sha256'; report_size_bytes='report_size_bytes'
        binding_sha256='binding_sha256'; binding_size_bytes='binding_size_bytes'
        raw_manifest_sha256='raw_manifest_sha256'; raw_manifest_size_bytes='raw_manifest_size_bytes'
        ordered_raw_report_set_sha256='ordered_raw_report_set_sha256'
        case_runtime_commitment_sha256='case_runtime_commitment_sha256'; case_count='case_count'
        process_identity_count='process_identity_count'; release_bundle_schema='release_bundle_schema'
        release_bundle_manifest_sha256='release_bundle_manifest_sha256'
        release_bundle_manifest_size_bytes='release_bundle_manifest_size_bytes'
        release_bundle_sha256s_sha256='release_bundle_sha256s_sha256'
        release_bundle_sha256s_size_bytes='release_bundle_sha256s_size_bytes'
        release_bundle_artifact_set_sha256='release_bundle_artifact_set_sha256'
        release_bundle_artifact_count='release_bundle_artifact_count'
        matrix_product_jar_set_sha256='matrix_product_jar_set_sha256'
        matrix_product_jar_count='matrix_product_jar_count'
    }
    foreach ($pair in $fieldMap.GetEnumerator()) {
        $actual = $receipt.([string]$pair.Key)
        $expected = $request.([string]$pair.Value)
        if (Test-JsonInteger $expected) {
            if (-not (Test-JsonInteger $actual) -or [long]$actual -ne [long]$expected) {
                throw "MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_BINDING_INVALID|$($pair.Key)"
            }
        } elseif ([string]$actual -cne [string]$expected) {
            throw "MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_BINDING_INVALID|$($pair.Key)"
        }
    }
    $signedAt = ConvertTo-EvidenceTime $receipt.signed_at
    $expiresAt = ConvertTo-EvidenceTime $receipt.expires_at
    # Producer and publisher accept the receipt only while the exchange is live.  Readiness
    # revalidates the immutable historical ordering/signature and therefore deliberately does
    # not compare this short-lived deadline with the current wall clock.
    if ($expiresAt.UtcDateTime.Ticks -ne $RequestValidation.expires_at.UtcDateTime.Ticks -or
            $signedAt -lt $RequestValidation.issued_at -or $signedAt -gt $expiresAt) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_EXPIRED_OR_TIME_INVALID'
    }
    try { $signature = [Convert]::FromBase64String([string]$receipt.signature_base64) }
    catch { throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_SIGNATURE_ENCODING_INVALID' }
    if ($signature.Length -ne $TrustRoot.modulus.Length -or
            -not (Test-MatrixRsaPkcs1Sha256Signature `
                (Get-MatrixSupervisorReceiptSigningPayload $receipt) $signature `
                $TrustRoot.modulus $TrustRoot.exponent)) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_SIGNATURE_INVALID'
    }
    return [pscustomobject]@{ value=$receipt; signed_at=$signedAt; expires_at=$expiresAt }
}

function Assert-MatrixNoSupervisorReplay(
        [object]$Receipt,
        [string]$CurrentIndexRelative) {
    $root = Join-Path $repoRoot $evidenceRootRelative
    foreach ($file in @(Get-ChildItem -LiteralPath $root -File `
            -Filter 'server-version-process-matrix-*.json' -ErrorAction Stop)) {
        $relative = $file.FullName.Substring($repoRoot.Length + 1).Replace('\','/')
        if ([string]$relative -ceq $CurrentIndexRelative) { continue }
        $document = Read-StrictRepoJson $relative $evidenceRootRelative $file.Name
        if ([string]$document.value.schema -cne
                'MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V4') { continue }
        $supervisorProperty = $document.value.PSObject.Properties['supervisor']
        if ($null -eq $supervisorProperty) {
            throw 'MCACE_RELEASE_MATRIX_REPLAY_INDEX_SUPERVISOR_INVALID'
        }
        if ([string]$supervisorProperty.Value.operation_attempt_id -ceq
                [string]$Receipt.operation_attempt_id -or
                [string]$supervisorProperty.Value.challenge_nonce -ceq
                    [string]$Receipt.challenge_nonce) {
            throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_RECEIPT_REPLAY_REJECTED'
        }
    }
}

function Assert-MatrixIndex([object]$Index, [string]$IndexRelative, [string]$RequestedCommit) {
    $indexNames = @('schema','evidence_id','generated_at','source_mode','source_commit',
        'artifact_source_commit','product_version','target_versions','expected_case_count',
        'observed_case_count','all_cases_passed','cleanup_all_zero','evidence_class',
        'independent_supervisor_signature_required','independent_supervisor_signature_present',
        'release_eligible','release_bundle','matrix_product_jars',
        'ordered_raw_report_set_sha256','supervisor','canonical_evidence')
    $artifactSourceCommit = Get-ReleaseArtifactSourceCommit
    $leaf = [IO.Path]::GetFileNameWithoutExtension($IndexRelative)
    if ([string]$Index.schema -in @(
            'MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V2',
            'MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V3')) {
        throw 'MCACE_RELEASE_MATRIX_V2_V3_NOT_RELEASE_ELIGIBLE'
    }
    if (-not (Test-ExactProperties $Index $indexNames) -or
            -not (Test-StringEqual $Index.schema 'MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V4') -or
            [string]$Index.evidence_id -cnotmatch '^server-version-process-matrix-[a-z0-9][a-z0-9._-]*$' -or
            [string]$Index.evidence_id -match '\.\.' -or
            -not (Test-StringEqual $Index.evidence_id $leaf) -or
            -not (Test-StringEqual $Index.source_mode 'EXECUTED') -or
            -not (Test-StringEqual $Index.source_commit $artifactSourceCommit) -or
            -not (Test-StringEqual $Index.artifact_source_commit $artifactSourceCommit) -or
            -not (Test-SourceProvenance $artifactSourceCommit $RequestedCommit) -or
            -not (Test-StringEqual $Index.product_version '0.0.1') -or
            -not (Test-JsonArray $Index.target_versions) -or
            ((@($Index.target_versions) -join ',') -cne '1.21.11,26.1.2,26.2') -or
            -not (Test-JsonInteger $Index.expected_case_count) -or [int]$Index.expected_case_count -ne 12 -or
            -not (Test-JsonInteger $Index.observed_case_count) -or [int]$Index.observed_case_count -ne 12 -or
            -not (Test-True $Index.all_cases_passed) -or -not (Test-True $Index.cleanup_all_zero) -or
            -not (Test-StringEqual $Index.evidence_class 'EXECUTED_EXTERNALLY_SUPERVISED_RELEASE_EVIDENCE') -or
            -not (Test-True $Index.independent_supervisor_signature_required) -or
            -not (Test-True $Index.independent_supervisor_signature_present) -or
            -not (Test-True $Index.release_eligible) -or
            -not (Test-Sha256 $Index.ordered_raw_report_set_sha256) -or
            -not (Test-ExactProperties $Index.canonical_evidence @(
                'report','binding','commit','raw_manifest','signing_request',
                'supervisor_receipt','raw_reports')) -or
            -not (Test-JsonArray $Index.canonical_evidence.raw_reports) -or
            @($Index.canonical_evidence.raw_reports).Count -ne 12) {
        throw 'MCACE_RELEASE_MATRIX_INDEX_V4_INVALID'
    }
    $indexGenerated = Assert-FreshEvidenceTime $Index.generated_at

    $bundleNames = @('schema','source_commit','artifact_source_commit','product_version',
        'manifest_sha256','manifest_size_bytes','sha256sums_sha256','sha256sums_size_bytes','artifacts')
    if (-not (Test-ExactProperties $Index.release_bundle $bundleNames) -or
            -not (Test-StringEqual $Index.release_bundle.schema 'MCACE_RELEASE_BUNDLE_V4') -or
            -not (Test-StringEqual $Index.release_bundle.source_commit $artifactSourceCommit) -or
            -not (Test-StringEqual $Index.release_bundle.artifact_source_commit $artifactSourceCommit) -or
            -not (Test-StringEqual $Index.release_bundle.product_version '0.0.1') -or
            -not (Test-Sha256 $Index.release_bundle.manifest_sha256) -or
            -not (Test-JsonInteger $Index.release_bundle.manifest_size_bytes) -or
            [long]$Index.release_bundle.manifest_size_bytes -le 0 -or
            -not (Test-Sha256 $Index.release_bundle.sha256sums_sha256) -or
            -not (Test-JsonInteger $Index.release_bundle.sha256sums_size_bytes) -or
            [long]$Index.release_bundle.sha256sums_size_bytes -le 0 -or
            -not (Test-JsonArray $Index.release_bundle.artifacts) -or
            @($Index.release_bundle.artifacts).Count -ne 6) {
        throw 'MCACE_RELEASE_MATRIX_BUNDLE_INDEX_INVALID'
    }
    if (-not (Test-BuildReleaseBundle $ReleaseBundleRoot $RequestedCommit $artifactSourceCommit)) {
        throw 'MCACE_RELEASE_MATRIX_PROTECTED_BUNDLE_INVALID'
    }
    $bundleRootAbsolute = ConvertTo-AbsoluteRepoPath $ReleaseBundleRoot
    $manifestDocument = Read-ReleaseLockedFileBytes `
        (Join-Path $bundleRootAbsolute 'release-manifest.properties') 64 1048576 'MATRIX_RELEASE_MANIFEST'
    $sumsDocument = Read-ReleaseLockedFileBytes `
        (Join-Path $bundleRootAbsolute 'SHA256SUMS') 64 1048576 'MATRIX_RELEASE_SHA256SUMS'
    # The externally supervised capture bundle is built at artifact commit A.  The protected
    # release bundle is rebuilt at the evidence-only descendant R and therefore has a different
    # manifest hash because source_commit changes from A to R.  Bind the current manifest through
    # Test-BuildReleaseBundle(R,A), require its canonical size to remain unchanged, and bind the
    # byte-identical deployable set through SHA256SUMS plus every JAR below.  Requiring the A
    # manifest hash to equal the R manifest hash would create an impossible tracked-evidence Git
    # fixed point.
    if ([long]$Index.release_bundle.manifest_size_bytes -ne [long]$manifestDocument.size_bytes -or
            [string]$Index.release_bundle.sha256sums_sha256 -cne [string]$sumsDocument.sha256 -or
            [long]$Index.release_bundle.sha256sums_size_bytes -ne [long]$sumsDocument.size_bytes) {
        throw 'MCACE_RELEASE_MATRIX_BUNDLE_CONTROL_FILE_BINDING_INVALID'
    }

    $bundleJarNames = @('mcace-client-fabric-1.21.11.jar','mcace-client-fabric-26.1.2.jar',
        'mcace-client-fabric-26.2.jar','mcace-server-bungeecord.jar',
        'mcace-server-paper.jar','mcace-server-velocity.jar')
    $bundleArtifacts = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $indexedBundleArtifacts = @($Index.release_bundle.artifacts)
    for ($artifactIndex = 0; $artifactIndex -lt $bundleJarNames.Count; $artifactIndex++) {
        $expectedFile = $bundleJarNames[$artifactIndex]
        $descriptor = $indexedBundleArtifacts[$artifactIndex]
        if (-not (Test-ExactProperties $descriptor @('file','sha256','size_bytes')) -or
                -not (Test-StringEqual $descriptor.file $expectedFile) -or
                -not (Test-Sha256 $descriptor.sha256) -or
                -not (Test-JsonInteger $descriptor.size_bytes) -or [long]$descriptor.size_bytes -le 0) {
            throw "MCACE_RELEASE_MATRIX_BUNDLE_ARTIFACT_DESCRIPTOR_INVALID|$expectedFile"
        }
        $artifact = Read-ReleaseLockedFileBytes (Join-Path $bundleRootAbsolute $expectedFile) `
            1024 134217728 'MATRIX_RELEASE_ARTIFACT'
        if ([string]$descriptor.sha256 -cne [string]$artifact.sha256 -or
                [long]$descriptor.size_bytes -ne [long]$artifact.size_bytes) {
            throw "MCACE_RELEASE_MATRIX_BUNDLE_ARTIFACT_BINDING_INVALID|$expectedFile"
        }
        $bundleArtifacts.Add($expectedFile, $descriptor)
    }

    $storedPrefix = "server-version-process-matrix/$($Index.evidence_id)"
    $repoPrefix = "$evidenceRootRelative/$storedPrefix"
    $expectedCases = @(Get-ExpectedMatrixCases)
    $expectedRawNames = @($expectedCases | ForEach-Object { "$($_.case_id).json" })
    Assert-MatrixEvidencePackageDirectory $repoPrefix $expectedRawNames
    $reportDoc = Read-MatrixJsonDescriptor $Index.canonical_evidence.report `
        "$storedPrefix/report.json" "$repoPrefix/report.json" $repoPrefix
    $bindingDoc = Read-MatrixJsonDescriptor $Index.canonical_evidence.binding `
        "$storedPrefix/binding.json" "$repoPrefix/binding.json" $repoPrefix
    $commitDoc = Read-MatrixJsonDescriptor $Index.canonical_evidence.commit `
        "$storedPrefix/commit.json" "$repoPrefix/commit.json" $repoPrefix
    $rawManifestDoc = Read-MatrixJsonDescriptor $Index.canonical_evidence.raw_manifest `
        "$storedPrefix/raw-manifest.json" "$repoPrefix/raw-manifest.json" $repoPrefix
    $signingRequestDoc = Read-MatrixJsonDescriptor $Index.canonical_evidence.signing_request `
        "$storedPrefix/supervisor-signing-request.json" `
        "$repoPrefix/supervisor-signing-request.json" $repoPrefix
    $supervisorReceiptDoc = Read-MatrixJsonDescriptor $Index.canonical_evidence.supervisor_receipt `
        "$storedPrefix/supervisor-receipt.json" `
        "$repoPrefix/supervisor-receipt.json" $repoPrefix
    $report = $reportDoc.value
    $binding = $bindingDoc.value
    $commit = $commitDoc.value
    $rawManifest = $rawManifestDoc.value

    $reportNames = @('schema','generated_at','source_mode','source_commit','release_source_commit',
        'artifact_source_commit','product_version',
        'target_versions','expected_case_count','observed_case_count','stable_case_count',
        'beta_case_count','all_cases_passed','cleanup_all_zero','raw_manifest_schema',
        'raw_manifest_sha256','raw_manifest_bytes','ordered_raw_report_set_sha256',
        'case_runtime_commitment_sha256','release_bundle_manifest_sha256',
        'release_bundle_artifact_set_sha256','matrix_product_jar_set_sha256',
        'supervisor_operation_attempt_id','supervisor_challenge_nonce',
        'supervisor_challenge_issued_at','supervisor_receipt_expires_at',
        'supervisor_trust_root_sha256','supervisor_signer_key_id',
        'supervisor_signature_algorithm','independent_supervisor_signature_present',
        'release_eligible','cases')
    if (-not (Test-ExactProperties $report $reportNames) -or
            -not (Test-StringEqual $report.schema 'MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V4') -or
            -not (Test-StringEqual $report.source_mode 'EXECUTED') -or
            -not (Test-StringEqual $report.source_commit $artifactSourceCommit) -or
            -not (Test-StringEqual $report.artifact_source_commit $artifactSourceCommit) -or
            -not (Test-StringEqual $report.release_source_commit `
                ([string]$Index.release_bundle.source_commit)) -or
            -not (Test-StringEqual $report.product_version '0.0.1') -or
            -not (Test-JsonArray $report.target_versions) -or
            ((@($report.target_versions) -join ',') -cne '1.21.11,26.1.2,26.2') -or
            -not (Test-JsonInteger $report.expected_case_count) -or [int]$report.expected_case_count -ne 12 -or
            -not (Test-JsonInteger $report.observed_case_count) -or [int]$report.observed_case_count -ne 12 -or
            -not (Test-JsonInteger $report.stable_case_count) -or [int]$report.stable_case_count -ne 10 -or
            -not (Test-JsonInteger $report.beta_case_count) -or [int]$report.beta_case_count -ne 2 -or
            -not (Test-True $report.all_cases_passed) -or -not (Test-True $report.cleanup_all_zero) -or
            -not (Test-StringEqual $report.raw_manifest_schema 'MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_MANIFEST_V1') -or
            -not (Test-Sha256 $report.raw_manifest_sha256) -or
            -not (Test-JsonInteger $report.raw_manifest_bytes) -or [long]$report.raw_manifest_bytes -le 0 -or
            -not (Test-Sha256 $report.ordered_raw_report_set_sha256) -or
            -not (Test-Sha256 $report.case_runtime_commitment_sha256) -or
            -not (Test-Sha256 $report.release_bundle_manifest_sha256) -or
            -not (Test-Sha256 $report.release_bundle_artifact_set_sha256) -or
            -not (Test-Sha256 $report.matrix_product_jar_set_sha256) -or
            [string]$report.supervisor_operation_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$report.supervisor_challenge_nonce -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-Sha256 $report.supervisor_trust_root_sha256) -or
            [string]$report.supervisor_signer_key_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$' -or
            -not (Test-StringEqual $report.supervisor_signature_algorithm 'RSA_PKCS1_SHA256') -or
            -not (Test-True $report.independent_supervisor_signature_present) -or
            -not (Test-True $report.release_eligible) -or
            -not (Test-JsonArray $report.cases) -or @($report.cases).Count -ne 12) {
        throw 'MCACE_RELEASE_MATRIX_REPORT_V4_INVALID'
    }
    $reportGenerated = Assert-FreshEvidenceTime $report.generated_at
    if ($indexGenerated.UtcDateTime.Ticks -ne $reportGenerated.UtcDateTime.Ticks) {
        throw 'MCACE_RELEASE_MATRIX_INDEX_REPORT_TIME_MISMATCH'
    }

    $caseNames = @('case_id','raw_schema','minecraft_version','minecraft_protocol','server_java_feature',
        'backend','proxy','lane','selector','invocation_started_at','invocation_finished_at','raw_report',
        'execution_mode','invocation_exit_code','invocation_log_sha256','raw_report_sha256',
        'raw_report_size','raw_report_last_write_at','server_asset_identity',
        'proxy_asset_identity','run_root','cleanup_process_count','remaining_run_process_count',
        'sensitive_artifact_count','process_cleanup_observed','passed')
    $runRootNames = @('proxy_jar_sha256','proxy_jar_size','backend_jar_sha256','backend_jar_size',
        'proxy_plugin_sha256','proxy_plugin_size','backend_plugin_sha256','backend_plugin_size',
        'prepared_tree_sha256','prepared_file_count','prepared_total_size')
    $seenOrdinal = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $seenFolded = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $cases = @($report.cases)
    for ($caseIndex = 0; $caseIndex -lt $cases.Count; $caseIndex++) {
        $case = $cases[$caseIndex]
        $expectedCase = $expectedCases[$caseIndex]
        $caseId = [string]$case.case_id
        if (-not (Test-ExactProperties $case $caseNames) -or
                -not (Test-ExactProperties $case.run_root $runRootNames) -or
                -not $seenOrdinal.Add($caseId) -or -not $seenFolded.Add($caseId) -or
                -not (Test-StringEqual $case.case_id ([string]$expectedCase.case_id)) -or
                -not (Test-JsonInteger $case.raw_schema) -or [int]$case.raw_schema -ne 4 -or
                -not (Test-StringEqual $case.minecraft_version ([string]$expectedCase.minecraft_version)) -or
                -not (Test-JsonInteger $case.minecraft_protocol) -or
                [int]$case.minecraft_protocol -ne [int]$expectedCase.minecraft_protocol -or
                -not (Test-JsonInteger $case.server_java_feature) -or
                [int]$case.server_java_feature -ne [int]$expectedCase.server_java_feature -or
                -not (Test-StringEqual $case.backend ([string]$expectedCase.backend)) -or
                -not (Test-StringEqual $case.proxy ([string]$expectedCase.proxy)) -or
                -not (Test-StringEqual $case.lane ([string]$expectedCase.lane)) -or
                -not (Test-StringEqual $case.selector ([string]$expectedCase.selector)) -or
                -not (Test-StringEqual $case.execution_mode 'EXECUTE') -or
                -not (Test-JsonInteger $case.invocation_exit_code) -or [int]$case.invocation_exit_code -ne 0 -or
                -not (Test-Sha256 $case.invocation_log_sha256) -or
                -not (Test-MatrixCanonicalRelativePath $case.raw_report) -or
                -not (Test-StringEqual $case.raw_report "raw/$caseId.json") -or
                -not (Test-Sha256 $case.raw_report_sha256) -or
                -not (Test-JsonInteger $case.raw_report_size) -or [long]$case.raw_report_size -le 0 -or
                -not (Test-NonEmptyJsonString $case.server_asset_identity) -or
                -not (Test-NonEmptyJsonString $case.proxy_asset_identity) -or
                -not (Test-JsonInteger $case.cleanup_process_count) -or [int]$case.cleanup_process_count -lt 2 -or
                -not (Test-JsonInteger $case.remaining_run_process_count) -or
                [int]$case.remaining_run_process_count -ne 0 -or
                -not (Test-JsonInteger $case.sensitive_artifact_count) -or
                [int]$case.sensitive_artifact_count -ne 0 -or
                -not (Test-True $case.process_cleanup_observed) -or -not (Test-True $case.passed)) {
            throw "MCACE_RELEASE_MATRIX_CASE_V4_INVALID|$caseIndex"
        }
        foreach ($name in @('proxy_jar_sha256','backend_jar_sha256','proxy_plugin_sha256',
                'backend_plugin_sha256','prepared_tree_sha256')) {
            if (-not (Test-Sha256 $case.run_root.$name)) {
                throw "MCACE_RELEASE_MATRIX_CASE_RUNTIME_HASH_INVALID|$caseId|$name"
            }
        }
        foreach ($name in @('proxy_jar_size','backend_jar_size','proxy_plugin_size',
                'backend_plugin_size','prepared_file_count','prepared_total_size')) {
            if (-not (Test-JsonInteger $case.run_root.$name) -or [long]$case.run_root.$name -le 0) {
                throw "MCACE_RELEASE_MATRIX_CASE_RUNTIME_SIZE_INVALID|$caseId|$name"
            }
        }
        $started = ConvertTo-EvidenceTime $case.invocation_started_at
        $finished = ConvertTo-EvidenceTime $case.invocation_finished_at
        $written = ConvertTo-EvidenceTime $case.raw_report_last_write_at
        if ($finished -lt $started -or $written -lt $started.AddSeconds(-2) -or
                $written -gt $finished.AddSeconds(2) -or $reportGenerated -lt $finished) {
            throw "MCACE_RELEASE_MATRIX_CASE_TIME_ORDER_INVALID|$caseId"
        }
    }
    if ($seenOrdinal.Count -ne 12 -or $seenFolded.Count -ne 12) {
        throw 'MCACE_RELEASE_MATRIX_CASE_SET_INVALID'
    }

    $rawManifestNames = @('schema','generated_at','source_mode','source_commit','product_version',
        'case_count','ordered_raw_report_set_sha256','reports')
    if (-not (Test-ExactProperties $rawManifest $rawManifestNames) -or
            -not (Test-StringEqual $rawManifest.schema 'MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_MANIFEST_V1') -or
            -not (Test-SameEvidenceTime $rawManifest.generated_at $report.generated_at) -or
            -not (Test-StringEqual $rawManifest.source_mode 'EXECUTED') -or
            -not (Test-StringEqual $rawManifest.source_commit $artifactSourceCommit) -or
            -not (Test-StringEqual $rawManifest.product_version '0.0.1') -or
            -not (Test-JsonInteger $rawManifest.case_count) -or [int]$rawManifest.case_count -ne 12 -or
            -not (Test-Sha256 $rawManifest.ordered_raw_report_set_sha256) -or
            -not (Test-JsonArray $rawManifest.reports) -or @($rawManifest.reports).Count -ne 12 -or
            [string]$report.raw_manifest_sha256 -cne [string]$rawManifestDoc.sha256 -or
            [long]$report.raw_manifest_bytes -ne [long]$rawManifestDoc.size_bytes) {
        throw 'MCACE_RELEASE_MATRIX_RAW_MANIFEST_INVALID'
    }
    $rawDescriptorNames = @('ordinal','case_id','path','sha256','size_bytes','raw_schema',
        'minecraft_version','backend','proxy','execution_mode','invocation_exit_code',
        'invocation_log_sha256','cleanup_process_count','remaining_run_process_count',
        'process_cleanup_observed')
    $manifestRawDescriptors = @($rawManifest.reports)
    $indexedRawDescriptors = @($Index.canonical_evidence.raw_reports)
    $rawDocuments = [Collections.Generic.List[object]]::new()
    for ($rawIndex = 0; $rawIndex -lt 12; $rawIndex++) {
        $descriptor = $manifestRawDescriptors[$rawIndex]
        $indexDescriptor = $indexedRawDescriptors[$rawIndex]
        $case = $cases[$rawIndex]
        $expectedCase = $expectedCases[$rawIndex]
        $expectedPath = "raw/$($expectedCase.case_id).json"
        if (-not (Test-ExactProperties $descriptor $rawDescriptorNames) -or
                -not (Test-JsonInteger $descriptor.ordinal) -or [int]$descriptor.ordinal -ne ($rawIndex + 1) -or
                -not (Test-StringEqual $descriptor.case_id ([string]$expectedCase.case_id)) -or
                -not (Test-StringEqual $descriptor.path $expectedPath) -or
                -not (Test-Sha256 $descriptor.sha256) -or
                -not (Test-JsonInteger $descriptor.size_bytes) -or [long]$descriptor.size_bytes -le 0 -or
                -not (Test-JsonInteger $descriptor.raw_schema) -or [int]$descriptor.raw_schema -ne 4 -or
                -not (Test-StringEqual $descriptor.minecraft_version ([string]$expectedCase.minecraft_version)) -or
                -not (Test-StringEqual $descriptor.backend ([string]$expectedCase.backend)) -or
                -not (Test-StringEqual $descriptor.proxy ([string]$expectedCase.proxy)) -or
                -not (Test-StringEqual $descriptor.execution_mode 'EXECUTE') -or
                -not (Test-JsonInteger $descriptor.invocation_exit_code) -or
                [int]$descriptor.invocation_exit_code -ne 0 -or
                -not (Test-Sha256 $descriptor.invocation_log_sha256) -or
                -not (Test-JsonInteger $descriptor.cleanup_process_count) -or
                [int]$descriptor.cleanup_process_count -ne [int]$case.cleanup_process_count -or
                -not (Test-JsonInteger $descriptor.remaining_run_process_count) -or
                [int]$descriptor.remaining_run_process_count -ne 0 -or
                -not (Test-True $descriptor.process_cleanup_observed) -or
                -not (Test-StringEqual $case.raw_report $expectedPath) -or
                -not (Test-StringEqual $case.raw_report_sha256 ([string]$descriptor.sha256)) -or
                [long]$case.raw_report_size -ne [long]$descriptor.size_bytes -or
                -not (Test-StringEqual $case.invocation_log_sha256 ([string]$descriptor.invocation_log_sha256))) {
            throw "MCACE_RELEASE_MATRIX_RAW_DESCRIPTOR_INVALID|$($expectedCase.case_id)"
        }
        $rawDocument = Read-MatrixJsonDescriptor $indexDescriptor `
            "$storedPrefix/$expectedPath" "$repoPrefix/$expectedPath" $repoPrefix
        if ([string]$rawDocument.sha256 -cne [string]$descriptor.sha256 -or
                [long]$rawDocument.size_bytes -ne [long]$descriptor.size_bytes) {
            throw "MCACE_RELEASE_MATRIX_RAW_BYTES_MISMATCH|$($expectedCase.case_id)"
        }
        Assert-MatrixRawReport $rawDocument.value $case $expectedCase
        [void]$rawDocuments.Add($rawDocument.value)
    }
    $orderedRawSetSha256 = Get-MatrixOrderedRawReportSetSha256 $manifestRawDescriptors $artifactSourceCommit
    if ([string]$rawManifest.ordered_raw_report_set_sha256 -cne $orderedRawSetSha256 -or
            [string]$report.ordered_raw_report_set_sha256 -cne $orderedRawSetSha256 -or
            [string]$Index.ordered_raw_report_set_sha256 -cne $orderedRawSetSha256) {
        throw 'MCACE_RELEASE_MATRIX_RAW_SET_BINDING_INVALID'
    }

    $bindingNames = @('schema','generated_at','report_schema','report_generated_at','report_sha256',
        'report_bytes','source_mode','source_commit','release_source_commit',
        'artifact_source_commit','product_version','raw_manifest_schema',
        'raw_manifest_sha256','raw_manifest_bytes','ordered_raw_report_set_sha256',
        'case_runtime_commitment_sha256','release_bundle_manifest_sha256',
        'release_bundle_artifact_set_sha256','matrix_product_jar_set_sha256',
        'supervisor_operation_attempt_id','supervisor_challenge_nonce',
        'supervisor_challenge_issued_at','supervisor_receipt_expires_at',
        'supervisor_trust_root_sha256','supervisor_signer_key_id',
        'supervisor_signature_algorithm','current_sha256','current',
        'independent_supervisor_signature_present','release_eligible','passed')
    if (-not (Test-ExactProperties $binding $bindingNames) -or
            -not (Test-StringEqual $binding.schema 'MCACE_SERVER_VERSION_PROCESS_MATRIX_BINDING_V4') -or
            -not (Test-StringEqual $binding.report_schema 'MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V4') -or
            -not (Test-SameEvidenceTime $binding.generated_at $report.generated_at) -or
            -not (Test-SameEvidenceTime $binding.report_generated_at $report.generated_at) -or
            -not (Test-StringEqual $binding.report_sha256 $reportDoc.sha256) -or
            -not (Test-JsonInteger $binding.report_bytes) -or
            [long]$binding.report_bytes -ne [long]$reportDoc.size_bytes -or
            -not (Test-StringEqual $binding.source_mode 'EXECUTED') -or
            -not (Test-StringEqual $binding.source_commit $artifactSourceCommit) -or
            -not (Test-StringEqual $binding.artifact_source_commit $artifactSourceCommit) -or
            -not (Test-StringEqual $binding.release_source_commit `
                ([string]$Index.release_bundle.source_commit)) -or
            -not (Test-StringEqual $binding.product_version '0.0.1') -or
            -not (Test-StringEqual $binding.raw_manifest_schema 'MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_MANIFEST_V1') -or
            -not (Test-StringEqual $binding.raw_manifest_sha256 ([string]$rawManifestDoc.sha256) ) -or
            -not (Test-JsonInteger $binding.raw_manifest_bytes) -or
            [long]$binding.raw_manifest_bytes -ne [long]$rawManifestDoc.size_bytes -or
            -not (Test-StringEqual $binding.ordered_raw_report_set_sha256 $orderedRawSetSha256) -or
            -not (Test-StringEqual $binding.case_runtime_commitment_sha256 ([string]$report.case_runtime_commitment_sha256)) -or
            -not (Test-StringEqual $binding.release_bundle_manifest_sha256 ([string]$report.release_bundle_manifest_sha256)) -or
            -not (Test-StringEqual $binding.release_bundle_artifact_set_sha256 ([string]$report.release_bundle_artifact_set_sha256)) -or
            -not (Test-StringEqual $binding.matrix_product_jar_set_sha256 ([string]$report.matrix_product_jar_set_sha256)) -or
            -not (Test-StringEqual $binding.supervisor_operation_attempt_id ([string]$report.supervisor_operation_attempt_id)) -or
            -not (Test-StringEqual $binding.supervisor_challenge_nonce ([string]$report.supervisor_challenge_nonce)) -or
            -not (Test-StringEqual $binding.supervisor_challenge_issued_at ([string]$report.supervisor_challenge_issued_at)) -or
            -not (Test-StringEqual $binding.supervisor_receipt_expires_at ([string]$report.supervisor_receipt_expires_at)) -or
            -not (Test-StringEqual $binding.supervisor_trust_root_sha256 ([string]$report.supervisor_trust_root_sha256)) -or
            -not (Test-StringEqual $binding.supervisor_signer_key_id ([string]$report.supervisor_signer_key_id)) -or
            -not (Test-StringEqual $binding.supervisor_signature_algorithm 'RSA_PKCS1_SHA256') -or
            -not (Test-Sha256 $binding.current_sha256) -or
            (Get-CompactObjectSha256 $binding.current) -cne [string]$binding.current_sha256 -or
            -not (Test-True $binding.independent_supervisor_signature_present) -or
            -not (Test-True $binding.release_eligible) -or
            -not (Test-True $binding.passed)) {
        throw 'MCACE_RELEASE_MATRIX_BINDING_V4_INVALID'
    }
    Assert-MatrixNativeCurrent $binding.current $report
    Assert-CurrentTrackedFileHash 'scripts/server-version-process-matrix.ps1' $binding.current.wrapper_sha256
    Assert-CurrentTrackedFileHash 'scripts/test-server-version-process-matrix.ps1' $binding.current.wrapper_test_sha256

    $commitNames = @('schema','generated_at','report_schema','binding_schema','report_sha256',
        'report_bytes','binding_sha256','binding_bytes','raw_manifest_schema','raw_manifest_sha256',
        'raw_manifest_bytes','ordered_raw_report_set_sha256','source_commit','release_source_commit',
        'artifact_source_commit','product_version','supervisor_signing_request_schema',
        'supervisor_signing_request_sha256','supervisor_signing_request_bytes',
        'supervisor_receipt_schema','supervisor_receipt_sha256','supervisor_receipt_bytes',
        'supervisor_operation_attempt_id','supervisor_challenge_nonce',
        'supervisor_trust_root_sha256','independent_supervisor_signature_present',
        'release_eligible','committed')
    if (-not (Test-ExactProperties $commit $commitNames) -or
            -not (Test-StringEqual $commit.schema 'MCACE_SERVER_VERSION_PROCESS_MATRIX_COMMIT_V4') -or
            -not (Test-StringEqual $commit.report_schema 'MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V4') -or
            -not (Test-StringEqual $commit.binding_schema 'MCACE_SERVER_VERSION_PROCESS_MATRIX_BINDING_V4') -or
            -not (Test-SameEvidenceTime $commit.generated_at $report.generated_at) -or
            -not (Test-StringEqual $commit.report_sha256 $reportDoc.sha256) -or
            -not (Test-JsonInteger $commit.report_bytes) -or
            [long]$commit.report_bytes -ne [long]$reportDoc.size_bytes -or
            -not (Test-StringEqual $commit.binding_sha256 $bindingDoc.sha256) -or
            -not (Test-JsonInteger $commit.binding_bytes) -or
            [long]$commit.binding_bytes -ne [long]$bindingDoc.size_bytes -or
            -not (Test-StringEqual $commit.raw_manifest_schema 'MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_MANIFEST_V1') -or
            -not (Test-StringEqual $commit.raw_manifest_sha256 ([string]$rawManifestDoc.sha256)) -or
            -not (Test-JsonInteger $commit.raw_manifest_bytes) -or
            [long]$commit.raw_manifest_bytes -ne [long]$rawManifestDoc.size_bytes -or
            -not (Test-StringEqual $commit.ordered_raw_report_set_sha256 $orderedRawSetSha256) -or
            -not (Test-StringEqual $commit.source_commit $artifactSourceCommit) -or
            -not (Test-StringEqual $commit.artifact_source_commit $artifactSourceCommit) -or
            -not (Test-StringEqual $commit.release_source_commit `
                ([string]$Index.release_bundle.source_commit)) -or
            -not (Test-StringEqual $commit.product_version '0.0.1') -or
            -not (Test-StringEqual $commit.supervisor_signing_request_schema 'MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_SIGNING_REQUEST_V1') -or
            -not (Test-StringEqual $commit.supervisor_signing_request_sha256 ([string]$signingRequestDoc.sha256)) -or
            -not (Test-JsonInteger $commit.supervisor_signing_request_bytes) -or
            [long]$commit.supervisor_signing_request_bytes -ne [long]$signingRequestDoc.size_bytes -or
            -not (Test-StringEqual $commit.supervisor_receipt_schema 'MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_RECEIPT_V1') -or
            -not (Test-StringEqual $commit.supervisor_receipt_sha256 ([string]$supervisorReceiptDoc.sha256)) -or
            -not (Test-JsonInteger $commit.supervisor_receipt_bytes) -or
            [long]$commit.supervisor_receipt_bytes -ne [long]$supervisorReceiptDoc.size_bytes -or
            -not (Test-StringEqual $commit.supervisor_operation_attempt_id ([string]$report.supervisor_operation_attempt_id)) -or
            -not (Test-StringEqual $commit.supervisor_challenge_nonce ([string]$report.supervisor_challenge_nonce)) -or
            -not (Test-StringEqual $commit.supervisor_trust_root_sha256 ([string]$report.supervisor_trust_root_sha256)) -or
            -not (Test-True $commit.independent_supervisor_signature_present) -or
            -not (Test-True $commit.release_eligible) -or
            -not (Test-True $commit.committed)) {
        throw 'MCACE_RELEASE_MATRIX_COMMIT_V4_INVALID'
    }

    if ([int]$Index.expected_case_count -ne [int]$report.expected_case_count -or
            [int]$Index.observed_case_count -ne [int]$report.observed_case_count -or
            -not (Test-True $Index.all_cases_passed) -or -not (Test-True $report.all_cases_passed) -or
            -not (Test-True $Index.cleanup_all_zero) -or -not (Test-True $report.cleanup_all_zero)) {
        throw 'MCACE_RELEASE_MATRIX_INDEX_REPORT_RESULT_MISMATCH'
    }

    if (-not (Test-JsonArray $Index.matrix_product_jars) -or
            @($Index.matrix_product_jars).Count -ne 3) {
        throw 'MCACE_RELEASE_MATRIX_PRODUCT_CROSS_BINDING_SET_INVALID'
    }
    $matrixRoles = @('velocity','bungee','paper')
    $matrixFiles = @('mcace-server-velocity.jar','mcace-server-bungeecord.jar','mcace-server-paper.jar')
    $matrixRelatives = @(
        'mcace-server-velocity/build/libs/mcace-server-velocity-0.0.1.jar',
        'mcace-server-bungeecord/build/libs/mcace-server-bungeecord-0.0.1.jar',
        'mcace-server-paper/build/libs/mcace-server-paper-0.0.1.jar')
    $matrixBindings = @($Index.matrix_product_jars)
    for ($matrixIndex = 0; $matrixIndex -lt 3; $matrixIndex++) {
        $entry = $matrixBindings[$matrixIndex]
        $role = $matrixRoles[$matrixIndex]
        $file = $matrixFiles[$matrixIndex]
        $native = $binding.current.product_jars.$role
        $bundle = $bundleArtifacts[$file]
        if (-not (Test-ExactProperties $entry @('role','bundle_file','matrix_relative','sha256','size_bytes')) -or
                -not (Test-StringEqual $entry.role $role) -or
                -not (Test-StringEqual $entry.bundle_file $file) -or
                -not (Test-StringEqual $entry.matrix_relative $matrixRelatives[$matrixIndex]) -or
                -not (Test-Sha256 $entry.sha256) -or
                -not (Test-JsonInteger $entry.size_bytes) -or [long]$entry.size_bytes -le 0 -or
                [string]$entry.sha256 -cne [string]$native.sha256 -or
                [long]$entry.size_bytes -ne [long]$native.size -or
                [string]$entry.sha256 -cne [string]$bundle.sha256 -or
                [long]$entry.size_bytes -ne [long]$bundle.size_bytes) {
            throw "MCACE_RELEASE_MATRIX_PRODUCT_CROSS_BINDING_INVALID|$role"
        }
    }

    $caseRuntimeCommitment = Get-MatrixCaseRuntimeCommitment `
        $report $rawDocuments.ToArray()
    $releaseArtifactCommitment = Get-MatrixReleaseArtifactCommitment `
        @($Index.release_bundle.artifacts)
    $matrixProductCommitment = Get-MatrixProductJarCommitment `
        @($Index.matrix_product_jars)
    if ([string]$report.case_runtime_commitment_sha256 -cne
            [string]$caseRuntimeCommitment.sha256 -or
            [string]$report.release_bundle_manifest_sha256 -cne
                [string]$Index.release_bundle.manifest_sha256 -or
            [string]$report.release_bundle_artifact_set_sha256 -cne
                [string]$releaseArtifactCommitment.sha256 -or
            [string]$report.matrix_product_jar_set_sha256 -cne
                [string]$matrixProductCommitment.sha256) {
        throw 'MCACE_RELEASE_MATRIX_V4_COMMITMENT_BINDING_INVALID'
    }

    $packageRootAbsolute = [IO.Path]::GetFullPath((Join-Path $repoRoot $repoPrefix))
    $trustRoot = Read-MatrixSupervisorTrustRootEvidence $packageRootAbsolute
    if ([string]$report.supervisor_trust_root_sha256 -cne
            [string]$trustRoot.document.sha256 -or
            [string]$report.supervisor_signer_key_id -cne [string]$trustRoot.value.key_id) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_REPORT_TRUST_BINDING_INVALID'
    }
    $signingRequest = Assert-MatrixSupervisorSigningRequest `
        $signingRequestDoc $reportDoc $bindingDoc $rawManifestDoc $report $Index `
        $caseRuntimeCommitment $releaseArtifactCommitment $matrixProductCommitment $trustRoot
    $supervisorReceipt = Assert-MatrixSupervisorReceipt `
        $supervisorReceiptDoc $signingRequest $trustRoot

    $supervisorNames = @('trust_root_schema','trust_root_sha256','signer_key_id',
        'signature_algorithm','operation_attempt_id','challenge_nonce','challenge_issued_at',
        'signed_at','expires_at','case_runtime_commitment_sha256','process_identity_count',
        'release_bundle_artifact_set_sha256','matrix_product_jar_set_sha256',
        'supervisor_independent','test_fixture')
    if (-not (Test-ExactProperties $Index.supervisor $supervisorNames) -or
            -not (Test-StringEqual $Index.supervisor.trust_root_schema 'MCACE_SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_V1') -or
            -not (Test-StringEqual $Index.supervisor.trust_root_sha256 ([string]$trustRoot.document.sha256)) -or
            -not (Test-StringEqual $Index.supervisor.signer_key_id ([string]$trustRoot.value.key_id)) -or
            -not (Test-StringEqual $Index.supervisor.signature_algorithm 'RSA_PKCS1_SHA256') -or
            -not (Test-StringEqual $Index.supervisor.operation_attempt_id ([string]$supervisorReceipt.value.operation_attempt_id)) -or
            -not (Test-StringEqual $Index.supervisor.challenge_nonce ([string]$supervisorReceipt.value.challenge_nonce)) -or
            -not (Test-StringEqual $Index.supervisor.challenge_issued_at ([string]$supervisorReceipt.value.challenge_issued_at)) -or
            -not (Test-StringEqual $Index.supervisor.signed_at ([string]$supervisorReceipt.value.signed_at)) -or
            -not (Test-StringEqual $Index.supervisor.expires_at ([string]$supervisorReceipt.value.expires_at)) -or
            -not (Test-StringEqual $Index.supervisor.case_runtime_commitment_sha256 ([string]$caseRuntimeCommitment.sha256)) -or
            -not (Test-JsonInteger $Index.supervisor.process_identity_count) -or
            [int]$Index.supervisor.process_identity_count -ne [int]$caseRuntimeCommitment.process_count -or
            -not (Test-StringEqual $Index.supervisor.release_bundle_artifact_set_sha256 ([string]$releaseArtifactCommitment.sha256)) -or
            -not (Test-StringEqual $Index.supervisor.matrix_product_jar_set_sha256 ([string]$matrixProductCommitment.sha256)) -or
            -not (Test-True $Index.supervisor.supervisor_independent) -or
            -not (Test-False $Index.supervisor.test_fixture) -or
            -not (Test-StringEqual $report.supervisor_operation_attempt_id ([string]$supervisorReceipt.value.operation_attempt_id)) -or
            -not (Test-StringEqual $report.supervisor_challenge_nonce ([string]$supervisorReceipt.value.challenge_nonce)) -or
            -not (Test-SameEvidenceTime $report.supervisor_challenge_issued_at $supervisorReceipt.value.challenge_issued_at) -or
            -not (Test-SameEvidenceTime $report.supervisor_receipt_expires_at $supervisorReceipt.value.expires_at)) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_INDEX_BINDING_INVALID'
    }

    Assert-MatrixNoSupervisorReplay $supervisorReceipt.value $IndexRelative

    # Final stable re-reads close the publish/readiness TOCTOU window.  The
    # trust root remains outside the repository; the signed request, receipt,
    # producer documents and every raw report remain pinned by exact bytes.
    $trustRootFinal = Read-MatrixLockedFileBytes $trustRoot.path 'supervisor-trust-root-final'
    if ([string]$trustRootFinal.sha256 -cne [string]$trustRoot.document.sha256 -or
            [long]$trustRootFinal.size_bytes -ne [long]$trustRoot.document.size_bytes -or
            (Get-MatrixApprovedSupervisorPin) -cne [string]$trustRoot.document.sha256) {
        throw 'MCACE_RELEASE_MATRIX_SUPERVISOR_TRUST_ROOT_CHANGED'
    }
    foreach ($role in @('report','binding','commit','raw_manifest','signing_request','supervisor_receipt')) {
        $descriptor = $Index.canonical_evidence.$role
        $finalPath = [IO.Path]::GetFullPath((Join-Path $repoRoot `
            ("$evidenceRootRelative/" + [string]$descriptor.path)))
        $finalDocument = Read-MatrixLockedFileBytes $finalPath "final:$role"
        if ([string]$finalDocument.sha256 -cne [string]$descriptor.sha256 -or
                [long]$finalDocument.size_bytes -ne [long]$descriptor.size_bytes) {
            throw "MCACE_RELEASE_MATRIX_FINAL_REREAD_MISMATCH|$role"
        }
    }
    foreach ($descriptor in @($Index.canonical_evidence.raw_reports)) {
        $finalPath = [IO.Path]::GetFullPath((Join-Path $repoRoot `
            ("$evidenceRootRelative/" + [string]$descriptor.path)))
        $finalDocument = Read-MatrixLockedFileBytes $finalPath 'final:raw-report'
        if ([string]$finalDocument.sha256 -cne [string]$descriptor.sha256 -or
                [long]$finalDocument.size_bytes -ne [long]$descriptor.size_bytes) {
            throw 'MCACE_RELEASE_MATRIX_FINAL_RAW_REREAD_MISMATCH'
        }
    }
    $finalManifest = Read-ReleaseLockedFileBytes `
        (Join-Path $bundleRootAbsolute 'release-manifest.properties') 64 1048576 `
        'MATRIX_RELEASE_MANIFEST_FINAL'
    $finalSums = Read-ReleaseLockedFileBytes `
        (Join-Path $bundleRootAbsolute 'SHA256SUMS') 64 1048576 `
        'MATRIX_RELEASE_SHA256SUMS_FINAL'
    if ([string]$finalManifest.identity -cne [string]$manifestDocument.identity -or
            [string]$finalManifest.sha256 -cne [string]$manifestDocument.sha256 -or
            [long]$finalManifest.size_bytes -ne [long]$manifestDocument.size_bytes -or
            [string]$finalSums.identity -cne [string]$sumsDocument.identity -or
            [string]$finalSums.sha256 -cne [string]$sumsDocument.sha256 -or
            [long]$finalSums.size_bytes -ne [long]$sumsDocument.size_bytes) {
        throw 'MCACE_RELEASE_MATRIX_RELEASE_BUNDLE_CHANGED'
    }
    foreach ($descriptor in @($Index.release_bundle.artifacts)) {
        $finalArtifact = Read-ReleaseLockedFileBytes `
            (Join-Path $bundleRootAbsolute ([string]$descriptor.file)) 1024 134217728 `
            'MATRIX_RELEASE_ARTIFACT_FINAL'
        if ([string]$finalArtifact.sha256 -cne [string]$descriptor.sha256 -or
                [long]$finalArtifact.size_bytes -ne [long]$descriptor.size_bytes) {
            throw "MCACE_RELEASE_MATRIX_RELEASE_ARTIFACT_CHANGED|$($descriptor.file)"
        }
    }
    $finalIndexDocument = Read-StrictRepoJson $IndexRelative $evidenceRootRelative `
        ([IO.Path]::GetFileName($IndexRelative))
    if ([string]$finalIndexDocument.sha256 -cne (Get-CompactObjectSha256 $Index)) {
        throw 'MCACE_RELEASE_MATRIX_INDEX_CHANGED_OR_NONCANONICAL'
    }

    return [pscustomobject]@{
        passed=$true; source_commit=[string]$Index.source_commit
        generated_at=ConvertTo-EvidenceTime $Index.generated_at; evidence=$IndexRelative
    }
}
function Assert-FederationNoEvidenceReplay(
        [object]$Index,
        [string]$CurrentIndexRelative) {
    $root = Join-Path $repoRoot $evidenceRootRelative
    foreach ($file in @(Get-ChildItem -LiteralPath $root -File -Force `
            -Filter 'federation-gui-handoff-*.json' -ErrorAction Stop)) {
        $relative = $file.FullName.Substring($repoRoot.Length + 1).Replace('\','/')
        if ([string]$relative -ceq $CurrentIndexRelative) { continue }
        $document = Read-StrictRepoJson $relative $evidenceRootRelative $file.Name
        if ([string]$document.value.schema -ceq
                'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V5' -and
                ([string]$document.value.gui_attempt_id -ceq [string]$Index.gui_attempt_id -or
                 [string]$document.value.gui_challenge_nonce -ceq [string]$Index.gui_challenge_nonce -or
                 [string]$document.value.postrun_operation_attempt_id -ceq
                    [string]$Index.postrun_operation_attempt_id -or
                 [string]$document.value.postrun_challenge_nonce -ceq
                    [string]$Index.postrun_challenge_nonce)) {
            throw 'MCACE_RELEASE_FEDERATION_V5_REPLAY_REJECTED'
        }
    }
}

function Assert-FederationIndexScalarFields([object]$Index) {
    foreach ($name in @('fabric_target','source_proxy','target_proxy',
            'gui_attempt_id','gui_challenge_nonce','postrun_operation_attempt_id',
            'postrun_challenge_nonce','release_bundle_fabric_jar_file')) {
        if (-not (Test-NonEmptyJsonString $Index.$name)) {
            throw "MCACE_RELEASE_FEDERATION_INDEX_STRING_TYPE_INVALID|$name"
        }
    }
}

function Assert-FederationIndex(
        [object]$Index,
        [string]$IndexRelative,
        [string]$RequestedCommit) {
    $indexNames = @(
        'schema','generated_at','source_commit','artifact_source_commit',
        'release_bundle_source_commit','fabric_target','source_proxy','target_proxy',
        'gui_attempt_id','gui_challenge_nonce','postrun_operation_attempt_id',
        'postrun_challenge_nonce',
        'visible_gui_trust_root_sha256','postrun_supervisor_trust_root_sha256',
        'postrun_signer_key_id','release_bundle_manifest_sha256',
        'release_bundle_fabric_jar_file','release_bundle_fabric_jar_sha256',
        'release_bundle_paper_jar_sha256','release_bundle_source_proxy_jar_sha256',
        'release_bundle_target_proxy_jar_sha256',
        'canonical_evidence')
    if (-not (Test-ExactProperties $Index $indexNames)) {
        throw 'MCACE_RELEASE_FEDERATION_INDEX_INVALID'
    }
    Assert-FederationIndexScalarFields $Index
    if (-not (Test-StringEqual $Index.schema 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V5') -or
            -not (Test-Commit $Index.source_commit) -or
            -not (Test-Commit $Index.artifact_source_commit) -or
            -not (Test-Commit $Index.release_bundle_source_commit) -or
            -not (Test-StringEqual $Index.source_commit ([string]$Index.artifact_source_commit)) -or
            -not (Test-StringEqual $Index.release_bundle_source_commit `
                ([string]$Index.artifact_source_commit)) -or
            -not (Test-SourceProvenance $Index.source_commit $RequestedCommit) -or
            [string]$Index.gui_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$Index.gui_challenge_nonce -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Index.postrun_operation_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$Index.postrun_challenge_nonce -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-Sha256 $Index.visible_gui_trust_root_sha256) -or
            -not (Test-Sha256 $Index.postrun_supervisor_trust_root_sha256) -or
            $Index.visible_gui_trust_root_sha256 -ceq $Index.postrun_supervisor_trust_root_sha256 -or
            $Index.postrun_signer_key_id -isnot [string] -or
            [string]$Index.postrun_signer_key_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$' -or
            -not (Test-Sha256 $Index.release_bundle_manifest_sha256) -or
            -not (Test-Sha256 $Index.release_bundle_fabric_jar_sha256) -or
            -not (Test-Sha256 $Index.release_bundle_paper_jar_sha256) -or
            -not (Test-Sha256 $Index.release_bundle_source_proxy_jar_sha256) -or
            -not (Test-Sha256 $Index.release_bundle_target_proxy_jar_sha256) -or
            -not (Test-ExactProperties $Index.canonical_evidence @(
                'report','binding','commit','visible_gui_attestation','visible_gui_signing_request',
                'visible_gui_screenshot','runtime_event_ledger','post_run_receipt'))) {
        throw 'MCACE_RELEASE_FEDERATION_INDEX_INVALID'
    }
    $artifactSourceCommit = Get-ReleaseArtifactSourceCommit
    if (-not (Test-StringEqual $Index.source_commit $artifactSourceCommit) -or
            -not (Test-StringEqual $Index.artifact_source_commit $artifactSourceCommit)) {
        throw 'MCACE_RELEASE_FEDERATION_ARTIFACT_SOURCE_MARKER_MISMATCH'
    }
    Assert-FederationNoEvidenceReplay $Index $IndexRelative
    if ([string]::IsNullOrWhiteSpace($VisibleGuiTrustRootPath) -or
            -not (Test-Sha256 $ExpectedVisibleGuiTrustRootSha256) -or
            -not (Test-StringEqual $ExpectedVisibleGuiTrustRootSha256 ([string]$Index.visible_gui_trust_root_sha256))) {
        throw 'MCACE_RELEASE_FEDERATION_GUI_TRUST_ROOT_PIN_REQUIRED_OR_MISMATCH'
    }
    if ([string]::IsNullOrWhiteSpace($PostRunSupervisorTrustRootPath) -or
            -not (Test-Sha256 $ExpectedPostRunSupervisorTrustRootSha256) -or
            -not (Test-StringEqual $ExpectedPostRunSupervisorTrustRootSha256 `
                ([string]$Index.postrun_supervisor_trust_root_sha256))) {
        throw 'MCACE_RELEASE_FEDERATION_POSTRUN_TRUST_ROOT_PIN_REQUIRED_OR_MISMATCH'
    }
    if ([string]$ExpectedVisibleGuiTrustRootSha256 -ceq
            [string]$ExpectedPostRunSupervisorTrustRootSha256) {
        throw 'MCACE_RELEASE_FEDERATION_SIGNER_PINS_MUST_DIFFER'
    }
    $target = [string]$Index.fabric_target
    if ($target -notin @('1.21.11','26.1.2','26.2') -or
            [string]$Index.source_proxy -notin @('VELOCITY','BUNGEE') -or
            [string]$Index.target_proxy -notin @('VELOCITY','BUNGEE') -or
            [string]$Index.release_bundle_fabric_jar_file -cne
                "mcace-client-fabric-$target.jar") {
        throw 'MCACE_RELEASE_FEDERATION_INDEX_ROUTE_OR_TARGET_INVALID'
    }
    $indexGeneratedAt = Assert-FreshEvidenceTime $Index.generated_at
    $leaf = [IO.Path]::GetFileNameWithoutExtension($IndexRelative)
    $prefix = "$evidenceRootRelative/federation-gui-handoff/$leaf"
    Assert-ExactEvidenceDirectory $prefix @(
        'report.json','binding.json','commit.json','visible-gui-attestation.json',
        'visible-gui-signing-request.json','visible-gui.png','runtime-events.jsonl',
        'post-run-receipt.json')
    $reportDoc = Read-JsonDescriptor $Index.canonical_evidence.report `
        "$prefix/report.json" $prefix
    $bindingDoc = Read-JsonDescriptor $Index.canonical_evidence.binding `
        "$prefix/binding.json" $prefix
    $commitDoc = Read-JsonDescriptor $Index.canonical_evidence.commit `
        "$prefix/commit.json" $prefix
    $attestationDoc = Read-JsonDescriptor $Index.canonical_evidence.visible_gui_attestation `
        "$prefix/visible-gui-attestation.json" $prefix
    $signingRequestDoc = Read-JsonDescriptor `
        $Index.canonical_evidence.visible_gui_signing_request `
        "$prefix/visible-gui-signing-request.json" $prefix
    $screenshotDoc = Read-BinaryDescriptor $Index.canonical_evidence.visible_gui_screenshot `
        "$prefix/visible-gui.png" $prefix
    $ledgerDoc = Read-BinaryDescriptor $Index.canonical_evidence.runtime_event_ledger `
        "$prefix/runtime-events.jsonl" $prefix
    $postRunReceiptDoc = Read-JsonDescriptor $Index.canonical_evidence.post_run_receipt `
        "$prefix/post-run-receipt.json" $prefix
    foreach ($item in @(
            [pscustomobject]@{ raw=$reportDoc.raw; role='report' },
            [pscustomobject]@{ raw=$bindingDoc.raw; role='binding' },
            [pscustomobject]@{ raw=$commitDoc.raw; role='commit' },
            [pscustomobject]@{ raw=$attestationDoc.raw; role='visible-gui-attestation' },
            [pscustomobject]@{ raw=$signingRequestDoc.raw; role='visible-gui-signing-request' },
            [pscustomobject]@{ raw=$postRunReceiptDoc.raw; role='post-run-receipt' })) {
        Assert-FederationSanitizedJsonRaw $item.raw $item.role
    }
    if ($ledgerDoc.bytes.Length -ge 3 -and $ledgerDoc.bytes[0] -eq 0xEF -and
            $ledgerDoc.bytes[1] -eq 0xBB -and $ledgerDoc.bytes[2] -eq 0xBF) {
        throw 'MCACE_RELEASE_FEDERATION_RUNTIME_LEDGER_UTF8_BOM_REJECTED'
    }
    $ledgerRaw = [Text.UTF8Encoding]::new($false, $true).GetString($ledgerDoc.bytes)
    Assert-FederationSanitizedJsonRaw $ledgerRaw 'runtime-event-ledger'

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
    foreach ($property in @($bindingDoc.value.PSObject.Properties)) {
        if ($property.Name -cnotin $bindingMetadataNames) {
            $current[$property.Name] = $property.Value
        }
    }
    if (-not $current.Contains('source_commit') -or
            [string]$current.source_commit -cne $artifactSourceCommit) {
        throw 'MCACE_RELEASE_FEDERATION_CURRENT_SOURCE_COMMIT_INVALID'
    }

    $validator = New-ReadinessFederationV5ValidatorModule
    try {
        $pin = $ExpectedVisibleGuiTrustRootSha256.ToLowerInvariant()
        $postRunPin = $ExpectedPostRunSupervisorTrustRootSha256.ToLowerInvariant()
        $approvedPin = & $validator {
            Get-ApprovedReleaseSignerPin `
                'MCACE_RELEASE_APPROVED_FEDERATION_GUI_TRUST_ROOT_SHA256' 'GUI'
        }
        $approvedPostRunPin = & $validator {
            Get-ApprovedReleaseSignerPin `
                'MCACE_RELEASE_APPROVED_FEDERATION_POSTRUN_TRUST_ROOT_SHA256' 'POSTRUN'
        }
        if ($pin -cne $approvedPin -or $postRunPin -cne $approvedPostRunPin) {
            throw 'MCACE_RELEASE_FEDERATION_SIGNER_PIN_NOT_APPROVED'
        }
        if ($pin -ceq $postRunPin) {
            throw 'MCACE_RELEASE_FEDERATION_APPROVED_SIGNER_PINS_MUST_DIFFER'
        }
        & $validator {
            param($Target,$Pin,$PostRunPin,$MaximumAge)
            $script:FabricTarget = $Target
            $script:ExpectedVisibleGuiTrustRootSha256 = $Pin
            $script:ExpectedPostRunSupervisorTrustRootSha256 = $PostRunPin
            $script:MaximumReportAgeMinutes = $MaximumAge
            $script:fabricDescriptor = $script:fabricTargets[$Target]
            if ($null -eq $script:fabricDescriptor) {
                throw 'MCACE_RELEASE_FEDERATION_TARGET_DESCRIPTOR_MISSING'
            }
            # Assert-PassingReportRaw is imported from the federation runner and
            # compares the captured report against the runner's runtime-mode
            # identity.  The standalone readiness module has its own scope, so
            # initialise the same value explicitly before invoking that validator.
            $script:fabricRuntimeMode = if ([int]$script:fabricDescriptor.java_major -eq 21) {
                'PRODUCTION_FINAL_REMAP_RELEASE_JAR'
            } else { 'LOOM_FINAL_NAMED_RELEASE_JAR' }
        } $target $pin $postRunPin $MaximumEvidenceAgeMinutes
        $report = & $validator {
            param($Raw,$Current,$Source,$TargetProxy)
            Assert-PassingReportRaw $Raw $Current $Source $TargetProxy
        } $reportDoc.raw $current ([string]$Index.source_proxy) ([string]$Index.target_proxy)
        $binding = & $validator {
            param($Raw,$ReportSha,$Report,$Current)
            Assert-BindingRaw $Raw $ReportSha $Report $Current
        } $bindingDoc.raw $reportDoc.sha256 $report $current
        if (-not (Test-SameEvidenceTime $indexGeneratedAt $report.generated_at)) {
            throw 'MCACE_RELEASE_FEDERATION_INDEX_REPORT_TIME_MISMATCH'
        }
        Assert-CurrentTrackedFileHash 'scripts/fabric-federation-gui-handoff-smoke.ps1' `
            $binding.wrapper_sha256
        Assert-CurrentTrackedFileHash 'scripts/test-fabric-federation-gui-handoff-smoke.ps1' `
            $binding.wrapper_test_sha256
        Assert-CurrentTrackedFileHash 'scripts/platform-load-smoke.ps1' `
            $binding.platform_wrapper_sha256

        $releaseBinding = & $validator {
            param($Root,$BundleCommit,$ArtifactCommit,$Target,$SourceProxy,$TargetProxy)
            Get-ReleaseBundleTargetBinding $Root $BundleCommit $ArtifactCommit $Target $SourceProxy $TargetProxy
        } (ConvertTo-AbsoluteRepoPath $ReleaseBundleRoot) $RequestedCommit $artifactSourceCommit $target `
            ([string]$Index.source_proxy) ([string]$Index.target_proxy)
        # The signed V5 run binds the capture bundle at artifact commit A.  The protected
        # release bundle is reconstructed at the evidence-only descendant R, so its manifest
        # legitimately differs only in release metadata.  Require R/A on the current bundle and
        # exact equality for every runtime JAR; keep the historical A manifest bound by the
        # signed report/index instead of requiring an impossible tracked-evidence fixed point.
        if ([string]$releaseBinding.bundle_source_commit -cne $RequestedCommit -or
                [string]$Index.release_bundle_source_commit -cne $artifactSourceCommit -or
                [string]$releaseBinding.artifact_source_commit -cne $artifactSourceCommit -or
                [string]$releaseBinding.fabric_jar_file -cne
                    [string]$Index.release_bundle_fabric_jar_file -or
                [string]$releaseBinding.fabric_jar_sha256 -cne
                    [string]$Index.release_bundle_fabric_jar_sha256 -or
                [string]$releaseBinding.paper_jar_sha256 -cne
                    [string]$Index.release_bundle_paper_jar_sha256 -or
                [string]$releaseBinding.source_proxy_jar_sha256 -cne
                    [string]$Index.release_bundle_source_proxy_jar_sha256 -or
                [string]$releaseBinding.target_proxy_jar_sha256 -cne
                    [string]$Index.release_bundle_target_proxy_jar_sha256 -or
                [string]$releaseBinding.fabric_jar_sha256 -cne
                    [string]$current.fabric_artifact_sha256 -or
                [string]$releaseBinding.fabric_jar_sha256 -cne
                    [string]$report.fabric_codesource_sha256_observed -or
                [string]$releaseBinding.fabric_jar_sha256 -cne
                    [string]$report.release_bundle_fabric_jar_sha256 -or
                [string]$report.release_bundle_fabric_jar_file -cne
                    [string]$releaseBinding.fabric_jar_file -or
                [long]$report.release_bundle_fabric_jar_size_bytes -ne
                    [long]$releaseBinding.fabric_jar_size_bytes) {
            throw 'MCACE_RELEASE_FEDERATION_PROTECTED_FINAL_JAR_CROSS_GATE_INVALID'
        }
        if ([string]$Index.release_bundle_manifest_sha256 -cne
                [string]$report.release_bundle_manifest_sha256 -or
                [string]$Index.release_bundle_fabric_jar_sha256 -cne
                    [string]$report.release_bundle_fabric_jar_sha256 -or
                [string]$Index.visible_gui_trust_root_sha256 -cne
                    [string]$report.operator_visible_gui_trust_root_sha256) {
            throw 'MCACE_RELEASE_FEDERATION_INDEX_REPORT_BINDING_INVALID'
        }

        $trustRootDoc = Read-VisibleGuiTrustRootEvidence $VisibleGuiTrustRootPath
        $postRunTrustRootDoc = Read-PostRunSupervisorTrustRootEvidence `
            $PostRunSupervisorTrustRootPath
        if ([string]::Equals([string]$trustRootDoc.absolute, [string]$postRunTrustRootDoc.absolute,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'MCACE_RELEASE_FEDERATION_TRUST_ROOT_PATHS_MUST_DIFFER'
        }
        $null = & $validator {
            param($GuiRoot,$GuiPin,$ApprovedGuiPin,$PostRoot,$PostPin,$ApprovedPostPin)
            $gui = Assert-VisibleGuiTrustRoot $GuiRoot $GuiPin $ApprovedGuiPin
            $post = Assert-PostRunSupervisorTrustRoot $PostRoot $PostPin $ApprovedPostPin
            Assert-DistinctFederationSignerRoots $gui $post
        } $trustRootDoc $pin $approvedPin $postRunTrustRootDoc $postRunPin $approvedPostRunPin
        $requestPreview = $signingRequestDoc.value
        $requestExpected = [ordered]@{}
        foreach ($name in @($requestPreview.PSObject.Properties.Name)) {
            $requestExpected[$name] = $requestPreview.$name
        }
        $validatedSigningRequest = & $validator {
            param($Evidence,$Screenshot,$Expected,$Accepted)
            Assert-VisibleGuiSigningRequest $Evidence $Screenshot $Expected $Accepted
        } $signingRequestDoc $screenshotDoc $requestExpected `
            (ConvertTo-EvidenceTime $report.enablement_consent_accepted_at)
        if ([string]$signingRequestDoc.sha256 -cne
                    [string]$report.operator_visible_gui_signing_request_sha256 -or
                [long]$signingRequestDoc.size_bytes -ne
                    [long]$report.operator_visible_gui_signing_request_size_bytes -or
                [string]$requestPreview.schema -cne
                    [string]$report.operator_visible_gui_signing_request_schema -or
                [string]$requestPreview.domain -cne
                    [string]$report.operator_visible_gui_signing_request_domain -or
                [string]$requestPreview.source_commit -cne $artifactSourceCommit -or
                [string]$requestPreview.artifact_source_commit -cne $artifactSourceCommit -or
                [string]$requestPreview.product_version -cne
                    [string]$releaseBinding.product_version -or
                [string]$requestPreview.fabric_target -cne $target -or
                [string]$requestPreview.source_proxy -cne [string]$Index.source_proxy -or
                [string]$requestPreview.target_proxy -cne [string]$Index.target_proxy -or
                [string]$requestPreview.release_bundle_manifest_sha256 -cne
                    [string]$Index.release_bundle_manifest_sha256 -or
                [string]$requestPreview.final_fabric_jar_sha256 -cne
                    [string]$releaseBinding.fabric_jar_sha256 -or
                [string]$requestPreview.run_attempt_id -cne [string]$report.run_attempt_id -or
                [string]$requestPreview.gui_attempt_id -cne [string]$report.gui_attempt_id -or
                [string]$requestPreview.challenge_nonce -cne
                    [string]$report.gui_challenge_nonce -or
                [string]$requestPreview.request_created_at -cne
                    [string]$report.gui_signing_request_created_at -or
                [string]$requestPreview.expires_at -cne
                    [string]$report.gui_signing_request_expires_at -or
                [string]$requestPreview.signing_request_path_sha256 -cne
                    [string]$report.operator_visible_gui_signing_request_path_sha256 -or
                [string]$requestPreview.screenshot_path_sha256 -cne
                    [string]$report.operator_visible_gui_screenshot_path_sha256 -or
                [string]$requestPreview.attestation_output_path_sha256 -cne
                    [string]$report.operator_visible_gui_attestation_output_path_sha256) {
            throw 'MCACE_RELEASE_FEDERATION_SIGNING_REQUEST_REPORT_BINDING_INVALID'
        }
        $attestation = & $validator {
            param($Evidence,$Screenshot,$RequestEvidence,$Request,$Trust,$Pin,$Prompt,$Accepted,
                $Commit,$Target,$Jar,$Attempt,$GuiAttempt,$Challenge,$Issued,$ProcessId,$Started,
                $ApprovedPin)
            Assert-VisibleGuiAttestation $Evidence $Screenshot $RequestEvidence $Request `
                $Trust $Pin $Prompt $Accepted $Commit $Target $Jar $Attempt $GuiAttempt `
                $Challenge $Issued $ProcessId $Started $ApprovedPin
        } $attestationDoc $screenshotDoc $signingRequestDoc $validatedSigningRequest `
            $trustRootDoc $pin `
            (ConvertTo-EvidenceTime $report.gui_prompt_rendered_at) `
            (ConvertTo-EvidenceTime $report.enablement_consent_accepted_at) `
            $artifactSourceCommit $target ([string]$releaseBinding.fabric_jar_sha256) `
            ([string]$report.run_attempt_id) ([string]$report.gui_attempt_id) `
            ([string]$report.gui_challenge_nonce) `
            (ConvertTo-EvidenceTime $report.gui_challenge_issued_at) `
            ([int]$report.operator_visible_gui_client_process_id) `
            ([string]$report.operator_visible_gui_client_process_started_at) $approvedPin
        $ledger = & $validator {
            param($Bytes,$Commit,$Target,$Attempt,$Challenge)
            Assert-RuntimeLedgerBytes $Bytes $Commit $Target $Attempt $Challenge
        } $ledgerDoc.bytes $artifactSourceCommit $target ([string]$report.run_attempt_id) `
            ([string]$report.gui_challenge_nonce)

        if ([string]$attestationDoc.sha256 -cne
                [string]$report.operator_visible_gui_attestation_json_sha256 -or
                [long]$attestationDoc.size_bytes -ne
                    [long]$report.operator_visible_gui_attestation_json_size_bytes -or
                [string]$screenshotDoc.sha256 -cne
                    [string]$report.operator_visible_gui_screenshot_sha256 -or
                [long]$screenshotDoc.size_bytes -ne
                    [long]$report.operator_visible_gui_screenshot_size_bytes -or
                [string]$attestation.screenshot_decoded_pixel_sha256 -cne
                    [string]$report.operator_visible_gui_screenshot_decoded_pixel_sha256 -or
                [string]$ledgerDoc.sha256 -cne [string]$report.runtime_ledger_sha256 -or
                [long]$ledgerDoc.size_bytes -ne [long]$report.runtime_ledger_size_bytes -or
                [int]$ledger.event_count -ne [int]$report.runtime_ledger_event_count -or
                [string]$ledger.head_sha256 -cne [string]$report.runtime_ledger_head_sha256 -or
                [string]$ledger.supervisor_seal_sha256 -cne
                    [string]$report.runtime_ledger_supervisor_seal_sha256 -or
                [string]$ledger.gui_receipt_attestation_sha256 -cne
                    [string]$attestationDoc.sha256) {
            throw 'MCACE_RELEASE_FEDERATION_SIGNED_GUI_LEDGER_HASH_CHAIN_INVALID'
        }
        foreach ($name in @(
                'source_negative_attempt_id','source_negative_peer',
                'source_negative_connection_id','source_negative_session_id',
                'source_negative_subject_commitment_sha256','target_negative_attempt_id',
                'target_negative_peer','target_negative_connection_id',
                'target_negative_session_id','target_negative_subject_commitment_sha256')) {
            if ([string]$ledger.$name -cne [string]$report.$name) {
                throw "MCACE_RELEASE_FEDERATION_RUNTIME_CORRELATION_INVALID|$name"
            }
        }
        $evidenceReleaseBinding = [pscustomobject]@{
            bundle_source_commit=[string]$Index.release_bundle_source_commit
            artifact_source_commit=$artifactSourceCommit
            product_version=[string]$releaseBinding.product_version
            manifest_sha256=[string]$Index.release_bundle_manifest_sha256
            fabric_jar_file=[string]$releaseBinding.fabric_jar_file
            fabric_jar_sha256=[string]$releaseBinding.fabric_jar_sha256
            fabric_jar_size_bytes=[long]$releaseBinding.fabric_jar_size_bytes
            paper_jar_sha256=[string]$releaseBinding.paper_jar_sha256
            source_proxy_jar_sha256=[string]$releaseBinding.source_proxy_jar_sha256
            target_proxy_jar_sha256=[string]$releaseBinding.target_proxy_jar_sha256
        }
        $postRunExpected = & $validator {
            param($Release,$Report,$ReportEvidence,$BindingEvidence,$AttestationEvidence,
                $ScreenshotEvidence,$Attestation,$LedgerEvidence,$Ledger,$Operation,$Challenge,
                $Issued)
            Get-PostRunReceiptExpectedBinding $Release $Report $ReportEvidence $BindingEvidence `
                $AttestationEvidence $ScreenshotEvidence $Attestation $LedgerEvidence $Ledger `
                $Operation $Challenge $Issued
        } $evidenceReleaseBinding $report $reportDoc $bindingDoc $attestationDoc $screenshotDoc `
            $attestation $ledgerDoc $ledger `
            ([string]$postRunReceiptDoc.value.postrun_operation_attempt_id) `
            ([string]$postRunReceiptDoc.value.postrun_challenge_nonce) `
            ([string]$postRunReceiptDoc.value.postrun_challenge_issued_at)
        $postRunReceipt = & $validator {
            param($Evidence,$Trust,$Pin,$ApprovedPin,$Expected,$Issued)
            Assert-PostRunReceipt $Evidence $Trust $Pin $ApprovedPin $Expected $Issued
        } $postRunReceiptDoc $postRunTrustRootDoc $postRunPin $approvedPostRunPin `
            $postRunExpected `
            (ConvertTo-EvidenceTime $postRunReceiptDoc.value.postrun_challenge_issued_at)
        if ([string]$postRunReceipt.value.signer_key_id -cne [string]$Index.postrun_signer_key_id -or
                [string]$postRunReceipt.value.signer_trust_root_sha256 -cne
                    [string]$Index.postrun_supervisor_trust_root_sha256) {
            throw 'MCACE_RELEASE_FEDERATION_POSTRUN_INDEX_SIGNER_BINDING_INVALID'
        }
        $null = & $validator {
            param($Raw,$ReportSha,$BindingSha,$Report,$ReceiptEvidence,$Receipt)
            Assert-CommitRaw $Raw $ReportSha $BindingSha $Report $ReceiptEvidence $Receipt
        } $commitDoc.raw $reportDoc.sha256 $bindingDoc.sha256 $report `
            $postRunReceiptDoc $postRunReceipt.value
        return [pscustomobject]@{
            passed=$true; source_commit=$artifactSourceCommit
            artifact_source_commit=$artifactSourceCommit
            release_bundle_source_commit=[string]$releaseBinding.bundle_source_commit
            fabric_target=$target
            final_fabric_jar_file=[string]$releaseBinding.fabric_jar_file
            final_fabric_jar_sha256=[string]$releaseBinding.fabric_jar_sha256
            generated_at=ConvertTo-EvidenceTime $Index.generated_at; evidence=$IndexRelative
            external_operator_visible_gui_attestation=$true
            cryptographic_external_receipt=$true
            append_only_runtime_ledger=$true
            external_postrun_supervisor_receipt=$true
        }
    } finally { Remove-Module $validator -Force -ErrorAction SilentlyContinue }
}

function Assert-VulcanIndex(
        [object]$Index,
        [string]$IndexRelative,
        [string]$RequestedCommit) {
    if ($null -ne $Index -and
            $Index.PSObject.Properties.Name -ccontains 'schema' -and
            (Test-StringEqual $Index.schema 'MCACE_VULCAN_GENUINE_EVENT_EVIDENCE_INDEX_V2')) {
        throw 'MCACE_RELEASE_VULCAN_V2_DIAGNOSTIC_NOT_RELEASE_GRADE'
    }
    $names=@(
        'schema','generated_at','source_mode','source_commit','artifact_source_commit',
        'product_version','release_eligible','fixture','run_attempt_id','challenge_nonce',
        'supervisor_trust_root_sha256','supervisor_signer_key_id','receipt_issued_at',
        'receipt_expires_at','vulcan_sha256','vulcan_size','upstream_paper_sha256',
        'upstream_paper_size','mcace_server_paper_sha256','mcace_server_paper_size',
        'callback_record_sha256','raw_event_sha256','callback_ledger_sha256',
        'provider_plugin_main_class','provider_event_class','accessor_provenance_sha256',
        'release_bundle_manifest_sha256','release_bundle_source_commit',
        'release_bundle_paper_jar_sha256','canonical_evidence')
    if (-not (Test-ExactProperties $Index $names) -or
            -not (Test-StringEqual $Index.schema 'MCACE_VULCAN_GENUINE_EVENT_EVIDENCE_INDEX_V3') -or
            -not (Test-StringEqual $Index.source_mode 'PUBLISHED_EXTERNALLY_SUPERVISED_VULCAN_V3') -or
            -not (Test-True $Index.release_eligible) -or -not (Test-False $Index.fixture) -or
            -not (Test-Commit $Index.source_commit) -or
            -not (Test-StringEqual $Index.artifact_source_commit ([string]$Index.source_commit)) -or
            -not (Test-StringEqual $Index.release_bundle_source_commit ([string]$Index.source_commit)) -or
            -not (Test-StringEqual $Index.product_version '0.0.1') -or
            [string]$Index.run_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$Index.challenge_nonce -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-Sha256 $Index.supervisor_trust_root_sha256) -or
            -not (Test-NonEmptyJsonString $Index.supervisor_signer_key_id)) {
        throw 'MCACE_RELEASE_VULCAN_V3_INDEX_INVALID'
    }
    $artifactSourceCommit=[string]$Index.artifact_source_commit
    if (-not (Test-SourceProvenance $artifactSourceCommit $RequestedCommit)) {
        throw 'MCACE_RELEASE_VULCAN_V3_SOURCE_PROVENANCE_INVALID'
    }
    foreach ($name in @('vulcan_sha256','upstream_paper_sha256','mcace_server_paper_sha256',
            'callback_record_sha256','raw_event_sha256','callback_ledger_sha256',
            'accessor_provenance_sha256','release_bundle_manifest_sha256',
            'release_bundle_paper_jar_sha256')) {
        if (-not (Test-Sha256 $Index.$name)) {
            throw "MCACE_RELEASE_VULCAN_V3_INDEX_HASH_INVALID|$name"
        }
    }
    foreach ($name in @('vulcan_size','upstream_paper_size','mcace_server_paper_size')) {
        if (-not (Test-JsonInteger $Index.$name) -or [long]$Index.$name -le 0) {
            throw "MCACE_RELEASE_VULCAN_V3_INDEX_SIZE_INVALID|$name"
        }
    }
    if ([string]$Index.vulcan_sha256 -cne
            '7ee3a4fdd7e9da5269f9efc327478e507563e6e7df7abec2222acd3b499bc993') {
        throw 'MCACE_RELEASE_VULCAN_V3_UNREVIEWED_LICENSED_JAR'
    }
    $canonicalNames=@('report','binding','commit','signing_request','supervisor_receipt',
        'raw_risk_event','callback_provenance')
    if (-not (Test-ExactProperties $Index.canonical_evidence $canonicalNames)) {
        throw 'MCACE_RELEASE_VULCAN_V3_CANONICAL_EVIDENCE_INVALID'
    }
    $prefix=[IO.Path]::GetDirectoryName(
        ([string]$Index.canonical_evidence.report.path).Replace('/',[IO.Path]::DirectorySeparatorChar))
    $prefix=$prefix.Replace('\','/')
    if ([string]::IsNullOrWhiteSpace($prefix) -or
            -not $prefix.StartsWith('docs/evidence/vulcan-genuine-event/',
                [StringComparison]::Ordinal)) {
        throw 'MCACE_RELEASE_VULCAN_V3_EVIDENCE_PREFIX_INVALID'
    }
    $files=[ordered]@{
        report='report.json';binding='binding.json';commit='commit.json'
        signing_request='signing-request.json';supervisor_receipt='supervisor-receipt.json'
        raw_risk_event='raw-risk-event.json';callback_provenance='callback-provenance.jsonl'
    }
    Assert-ExactEvidenceDirectory $prefix @($files.Values)
    foreach($entry in $files.GetEnumerator()) {
        $expected="$prefix/$($entry.Value)"
        $null=if ($entry.Key -in @('raw_risk_event','callback_provenance')) {
            Read-BinaryDescriptor $Index.canonical_evidence.($entry.Key) $expected $prefix
        } else { Read-JsonDescriptor $Index.canonical_evidence.($entry.Key) $expected $prefix }
    }
    if ([string]::IsNullOrWhiteSpace($VulcanSupervisorTrustRootPath) -or
            [string]::IsNullOrWhiteSpace($ExpectedVulcanSupervisorTrustRootSha256) -or
            $ExpectedVulcanSupervisorTrustRootSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
            [string]$Index.supervisor_trust_root_sha256 -cne
                $ExpectedVulcanSupervisorTrustRootSha256.ToLowerInvariant()) {
        throw 'MCACE_RELEASE_VULCAN_V3_PROTECTED_TRUST_ROOT_REQUIRED'
    }
    $approvedPin=[Environment]::GetEnvironmentVariable(
        'MCACE_VULCAN_SUPERVISOR_TRUST_ROOT_SHA256','Process')
    if ([string]::IsNullOrWhiteSpace($approvedPin) -or
            $approvedPin -cnotmatch '^[0-9a-fA-F]{64}$' -or
            $approvedPin.ToLowerInvariant() -cne
                $ExpectedVulcanSupervisorTrustRootSha256.ToLowerInvariant()) {
        throw 'MCACE_RELEASE_VULCAN_V3_APPROVED_TRUST_ROOT_PIN_REQUIRED'
    }
    $trust=Read-VulcanSupervisorTrustRootEvidence $VulcanSupervisorTrustRootPath
    $currentPaper=Get-ProtectedReleaseBundleArtifactBinding $ReleaseBundleRoot `
        $RequestedCommit $artifactSourceCommit 'mcace-server-paper.jar'
    if ([string]$currentPaper.sha256 -cne [string]$Index.mcace_server_paper_sha256 -or
            [long]$currentPaper.size_bytes -ne [long]$Index.mcace_server_paper_size -or
            [string]$currentPaper.sha256 -cne [string]$Index.release_bundle_paper_jar_sha256) {
        throw 'MCACE_RELEASE_VULCAN_V3_CURRENT_RELEASE_PAPER_JAR_MISMATCH'
    }
    $validator=New-ReadinessVulcanV3ValidatorModule
    try {
        $validated=& $validator {
            param($Directory,$Trust,$Pin,$Approved,$Commit,$Vulcan,$Paper,$MCAce)
            Assert-VulcanV3Package $Directory $Trust $Pin $Approved $Commit `
                $Vulcan $Paper $MCAce
        } (ConvertTo-AbsoluteRepoPath $prefix) $trust `
            $ExpectedVulcanSupervisorTrustRootSha256 $approvedPin $artifactSourceCommit `
            ([string]$Index.vulcan_sha256) ([string]$Index.upstream_paper_sha256) `
            ([string]$Index.mcace_server_paper_sha256)
        if ([string]$validated.receipt.signer_key_id -cne
                [string]$Index.supervisor_signer_key_id -or
                [string]$validated.report.callback_record_sha256 -cne
                    [string]$Index.callback_record_sha256) {
            throw 'MCACE_RELEASE_VULCAN_V3_INDEX_RECEIPT_BINDING_INVALID'
        }
    } finally { Remove-Module $validator -Force -ErrorAction SilentlyContinue }
    $duplicates=0
    foreach($candidate in @(Get-ChildItem -LiteralPath (Join-Path $repoRoot $evidenceRootRelative) `
            -File -Force -Filter 'vulcan-genuine-event-*.json' -ErrorAction SilentlyContinue)) {
        try { $other=ConvertFrom-StrictJsonRaw ([IO.File]::ReadAllText($candidate.FullName)) }
        catch { continue }
        if ([string]$other.schema -ceq 'MCACE_VULCAN_GENUINE_EVENT_EVIDENCE_INDEX_V3' -and
                ([string]$other.run_attempt_id -ceq [string]$Index.run_attempt_id -or
                 [string]$other.challenge_nonce -ceq [string]$Index.challenge_nonce)) {
            $duplicates++
        }
    }
    if ($duplicates -ne 1) { throw 'MCACE_RELEASE_VULCAN_V3_REPLAY_REJECTED' }
    return [pscustomobject]@{
        passed=$true;source_commit=$artifactSourceCommit
        artifact_source_commit=$artifactSourceCommit
        release_bundle_source_commit=[string]$currentPaper.source_commit
        generated_at=ConvertTo-EvidenceTime $Index.generated_at;evidence=$IndexRelative
        cryptographic_external_receipt=$true;genuine_provider_callback=$true
        callback_runtime_provenance=$true;raw_event_bound=$true
    }
}

if (-not ('MCAceConstantTimeByteEqualityV1' -as [type])) {
    Add-Type -TypeDefinition @'
using System;

public static class MCAceConstantTimeByteEqualityV1 {
    public static bool Equals(byte[] left, byte[] right) {
        if (left == null || right == null || left.Length != right.Length) return false;
        int difference = 0;
        for (int i = 0; i < left.Length; i++) difference |= left[i] ^ right[i];
        return difference == 0;
    }
}
'@
}

function Test-ProductionAuthorityBytesEqual([byte[]]$Left, [byte[]]$Right) {
    return [MCAceConstantTimeByteEqualityV1]::Equals($Left, $Right)
}

function Read-ProductionAuthorityStreamExactly(
        [IO.Stream]$Stream,
        [int]$Length,
        [string]$Role) {
    $bytes = New-Object byte[] $Length
    $offset = 0
    while ($offset -lt $Length) {
        $read = $Stream.Read($bytes, $offset, $Length - $offset)
        if ($read -le 0) {
            throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_SHORT_READ|$Role"
        }
        $offset += $read
    }
    if ($Stream.ReadByte() -ne -1) {
        throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_TRAILING_READ|$Role"
    }
    return ,$bytes
}

function Read-ProductionAuthorityLockedFileBytes(
        [string]$Path,
        [long]$MinimumBytes,
        [long]$MaximumBytes,
        [string]$Role) {
    $absolute = [IO.Path]::GetFullPath($Path)
    Assert-ReleasePathChainNoReparse $absolute $true
    $item = Get-Item -LiteralPath $absolute -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($item.Attributes -band [IO.FileAttributes]::Hidden) -ne 0 -or
            ($item.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $item.LinkType)) {
        throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_REGULAR_NO_REPARSE_FILE_REQUIRED|$Role"
    }
    $before = Get-ReleaseNoFollowFileIdentity $absolute
    $stream = New-Object IO.FileStream(
        $absolute, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        $length = [long]$stream.Length
        if ($length -lt $MinimumBytes -or $length -gt $MaximumBytes -or
                $length -gt [int]::MaxValue) {
            throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_FILE_SIZE_INVALID|$Role|$length"
        }
        if (Test-ReleaseWindowsPlatform) {
            try {
                $handleIdentity = [MCAceReleaseReadinessFileIdentityV3]::FromHandle(
                    $stream.SafeFileHandle)
            } catch {
                throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_HANDLE_IDENTITY_FAILED|$Role"
            }
            if ($handleIdentity -cne $before) {
                throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_HANDLE_IDENTITY_CHANGED|$Role"
            }
        }
        $first = Read-ProductionAuthorityStreamExactly $stream ([int]$length) "$Role|first"
        $stream.Position = 0L
        $second = Read-ProductionAuthorityStreamExactly $stream ([int]$length) "$Role|second"
        if (-not (Test-ProductionAuthorityBytesEqual $first $second) -or
                [long]$stream.Length -ne $length) {
            throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_LOCKED_DOUBLE_READ_MISMATCH|$Role"
        }
    } finally {
        $stream.Dispose()
    }
    Assert-ReleasePathChainNoReparse $absolute $true
    if ((Get-ReleaseNoFollowFileIdentity $absolute) -cne $before) {
        throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_PATH_IDENTITY_CHANGED|$Role"
    }
    return [pscustomobject]@{
        absolute=$absolute; bytes=[byte[]]$first; size=[long]$first.Length
        size_bytes=[long]$first.Length; sha256=(Get-BytesSha256 $first)
        identity=$before; maximum_bytes=$MaximumBytes
    }
}

function Read-ProductionAuthorityDescriptor(
        [object]$Descriptor,
        [string]$ExpectedPath,
        [string]$Prefix,
        [long]$MaximumBytes,
        [string]$Role) {
    if (-not (Test-ExactProperties $Descriptor @('path','sha256','size_bytes')) -or
            -not (Test-StringEqual $Descriptor.path $ExpectedPath) -or
            -not (Test-Sha256 $Descriptor.sha256) -or
            -not (Test-JsonInteger $Descriptor.size_bytes) -or
            [long]$Descriptor.size_bytes -le 0 -or
            [long]$Descriptor.size_bytes -gt $MaximumBytes) {
        throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_DESCRIPTOR_INVALID|$Role"
    }
    $leaf = @($ExpectedPath.Split('/'))[-1]
    $absolute = Assert-CanonicalRepoRelativePath $ExpectedPath $Prefix $leaf
    $document = Read-ProductionAuthorityLockedFileBytes $absolute 1 $MaximumBytes $Role
    if ([string]$document.sha256 -cne [string]$Descriptor.sha256 -or
            [long]$document.size_bytes -ne [long]$Descriptor.size_bytes) {
        throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_DESCRIPTOR_BYTES_MISMATCH|$Role"
    }
    $document | Add-Member NoteProperty relative $ExpectedPath
    return $document
}

function ConvertTo-ProductionAuthorityEvidenceTime([object]$Value, [string]$Role) {
    if ($Value -isnot [string] -or
            [string]$Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3,7})?Z$') {
        throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_TIMESTAMP_INVALID|$Role"
    }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$parsed)) {
        throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_TIMESTAMP_INVALID|$Role"
    }
    return $parsed.ToUniversalTime()
}

function Assert-FreshProductionAuthorityEvidenceTime([object]$Value, [string]$Role) {
    $timestamp = ConvertTo-ProductionAuthorityEvidenceTime $Value $Role
    $age = [DateTimeOffset]::UtcNow - $timestamp
    if ($age.TotalMinutes -lt -5 -or $age.TotalMinutes -gt $MaximumEvidenceAgeMinutes) {
        throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_STALE_OR_FUTURE|$Role"
    }
    return $timestamp
}

function Assert-ProductionAuthorityHistoricalReceiptWindow(
        [DateTimeOffset]$IndexGenerated,
        [DateTimeOffset]$Issued,
        [DateTimeOffset]$Expires) {
    # Receipt expiry closes the live producer/publisher exchange.  Protected readiness
    # revalidates the immutable historical acceptance ordering and signature; it must not
    # permanently invalidate a package merely because the current wall clock moved past
    # that short exchange deadline.
    if ($Expires -le $Issued -or ($Expires - $Issued).TotalMinutes -gt 15 -or
            $IndexGenerated -lt $Issued -or $IndexGenerated -ge $Expires) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_INDEX_RECEIPT_WINDOW_INVALID'
    }
}

function Assert-ProductionAuthorityExactDirectory(
        [string]$Prefix,
        [string[]]$RootFiles,
        [string[]]$ArtifactLeaves) {
    if ([string]::IsNullOrWhiteSpace($Prefix) -or $Prefix.Contains('\') -or
            $Prefix.StartsWith('/') -or $Prefix.Contains(':') -or
            -not $Prefix.StartsWith(
                "$evidenceRootRelative/server-confirmed-production/",
                [StringComparison]::Ordinal)) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_DIRECTORY_PATH_INVALID'
    }
    if (@($RootFiles | Select-Object -Unique).Count -ne $RootFiles.Count -or
            @($ArtifactLeaves | Select-Object -Unique).Count -ne 10 -or
            $ArtifactLeaves.Count -ne 10) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_DIRECTORY_EXPECTED_SET_INVALID'
    }
    $absolute = [IO.Path]::GetFullPath((Join-Path $repoRoot $Prefix))
    Assert-ReleasePathChainNoReparse $absolute $true
    if (-not (Test-Path -LiteralPath $absolute -PathType Container)) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_DIRECTORY_REQUIRED'
    }
    $rootIdentity = Get-ReleaseNoFollowFileIdentity $absolute -Directory
    $entries = @(Get-ChildItem -LiteralPath $absolute -Force -ErrorAction Stop)
    $expectedRoot = @($RootFiles + 'artifacts' | Sort-Object)
    if ($entries.Count -ne $expectedRoot.Count -or
            ((@($entries.Name | Sort-Object) -join "`n") -cne
                ($expectedRoot -join "`n"))) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_DIRECTORY_ROOT_SET_INVALID'
    }
    foreach ($entry in $entries) {
        $isArtifactDirectory = [string]$entry.Name -ceq 'artifacts'
        if ([bool]$entry.PSIsContainer -ne $isArtifactDirectory -or
                ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($entry.Attributes -band [IO.FileAttributes]::Hidden) -ne 0 -or
                ($entry.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $entry.LinkType)) {
            throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_DIRECTORY_ENTRY_INVALID'
        }
    }
    $artifactDirectory = Join-Path $absolute 'artifacts'
    Assert-ReleasePathChainNoReparse $artifactDirectory $true
    $artifactIdentity = Get-ReleaseNoFollowFileIdentity $artifactDirectory -Directory
    $artifactEntries = @(Get-ChildItem -LiteralPath $artifactDirectory -Force -ErrorAction Stop)
    if ($artifactEntries.Count -ne 10 -or
            ((@($artifactEntries.Name | Sort-Object) -join "`n") -cne
                ((@($ArtifactLeaves | Sort-Object)) -join "`n"))) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_DIRECTORY_ARTIFACT_SET_INVALID'
    }
    foreach ($entry in $artifactEntries) {
        if ($entry.PSIsContainer -or
                ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($entry.Attributes -band [IO.FileAttributes]::Hidden) -ne 0 -or
                ($entry.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $entry.LinkType) -or
                [string]$entry.Name -cnotmatch '^[A-Za-z0-9._-]+\.(?:jar|bin)$') {
            throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_ARTIFACT_ENTRY_INVALID'
        }
    }
    return [pscustomobject]@{
        absolute=$absolute; root_identity=$rootIdentity
        artifact_directory=$artifactDirectory; artifact_identity=$artifactIdentity
    }
}

function Assert-ProductionAuthorityNoSupervisorReplay(
        [string]$OperationAttemptId,
        [string]$ChallengeSha256,
        [string]$CurrentIndexRelative) {
    $root = Join-Path $repoRoot $evidenceRootRelative
    foreach ($file in @(Get-ChildItem -LiteralPath $root -File -Force `
            -Filter 'server-confirmed-production-*.json' -ErrorAction Stop)) {
        $relative = $file.FullName.Substring($repoRoot.Length + 1).Replace('\','/')
        if ([string]$relative -ceq $CurrentIndexRelative) { continue }
        $absolute = Assert-CanonicalRepoRelativePath $relative $evidenceRootRelative $file.Name
        $snapshot = Read-ProductionAuthorityLockedFileBytes $absolute 1 2097152 `
            'authority-replay-index'
        $raw = [Text.UTF8Encoding]::new($false, $true).GetString($snapshot.bytes)
        $other = ConvertFrom-StrictJsonRaw $raw
        if ([string]$other.schema -cne
                'MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V4') { continue }
        if ([string]$other.operation_attempt_id -cnotmatch
                '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$' -or
                -not (Test-Sha256 $other.supervisor_challenge_sha256)) {
            throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_REPLAY_INDEX_INVALID'
        }
        if ([string]$other.operation_attempt_id -ceq $OperationAttemptId -or
                [string]$other.supervisor_challenge_sha256 -ceq $ChallengeSha256) {
            throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_REPLAY_REJECTED'
        }
    }
}

function Assert-ProductionAuthorityIndex(
        [object]$Index,
        [string]$IndexRelative,
        [string]$RequestedCommit) {
    if ([string]$Index.schema -in @(
            'MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V1',
            'MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V2',
            'MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V3')) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_V1_V3_NOT_RELEASE_ELIGIBLE'
    }
    $indexNames = @(
        'schema','generated_at','source_commit','artifact_source_commit','product_version',
        'evidence_class','release_eligible','capture_id','operation_attempt_id',
        'supervisor_challenge_sha256','supervisor_descriptor_sha256',
        'supervisor_key_id_sha256','supervisor_receipt_sha256','receipt_issued_at',
        'receipt_expires_at','raw_evidence_root_sha256','raw_frame_set_sha256',
        'provider_evidence_commitment_sha256','profile_sha256','topology_sha256',
        'selected_proxy','action_ceiling','release_bundle','canonical_evidence',
        'packaged_artifacts')
    $canonicalNames = @(
        'artifact_manifest','binding','capture_supervisor_public_descriptor','commit',
        'freeze_manifest','issuance_journal','paper_events','process_ledger',
        'provider_events','proxy_events','raw_capture_manifest','raw_frames','report',
        'supervisor_receipt')
    $artifactRoles = @(
        'java_runtime','minecraft_client','fabric_loader','mcace_client_fabric',
        'paper_server','mcace_server_paper','grim','vulcan','mcace_server_velocity',
        'mcace_server_bungeecord')
    $artifactSourceCommit = Get-ReleaseArtifactSourceCommit
    if (-not (Test-ExactProperties $Index $indexNames) -or
            -not (Test-StringEqual $Index.schema `
                'MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V4') -or
            -not (Test-StringEqual $Index.source_commit $artifactSourceCommit) -or
            -not (Test-StringEqual $Index.artifact_source_commit $artifactSourceCommit) -or
            -not (Test-SourceProvenance $artifactSourceCommit $RequestedCommit) -or
            -not (Test-StringEqual $Index.product_version '0.0.1') -or
            -not (Test-StringEqual $Index.evidence_class `
                'EXTERNAL_SUPERVISOR_SIGNED_RAW_REVALIDATED_PRODUCTION_AUTHORITY') -or
            -not (Test-True $Index.release_eligible) -or
            [string]$Index.capture_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$' -or
            [string]$Index.operation_attempt_id -cnotmatch
                '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$' -or
            [string]$Index.selected_proxy -cnotin @('velocity','bungeecord') -or
            -not (Test-StringEqual $Index.action_ceiling 'MONITOR') -or
            -not (Test-ExactProperties $Index.canonical_evidence $canonicalNames) -or
            -not (Test-ExactProperties $Index.packaged_artifacts $artifactRoles)) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_INDEX_V4_INVALID'
    }
    foreach ($hashName in @(
            'supervisor_challenge_sha256','supervisor_descriptor_sha256',
            'supervisor_key_id_sha256','supervisor_receipt_sha256',
            'raw_evidence_root_sha256','raw_frame_set_sha256',
            'provider_evidence_commitment_sha256','profile_sha256','topology_sha256')) {
        if (-not (Test-Sha256 $Index.$hashName)) {
            throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_INDEX_HASH_INVALID|$hashName"
        }
    }
    $indexGenerated = Assert-FreshProductionAuthorityEvidenceTime `
        $Index.generated_at 'index-generated-at'
    $issued = ConvertTo-ProductionAuthorityEvidenceTime $Index.receipt_issued_at `
        'index-receipt-issued-at'
    $expires = ConvertTo-ProductionAuthorityEvidenceTime $Index.receipt_expires_at `
        'index-receipt-expires-at'
    Assert-ProductionAuthorityHistoricalReceiptWindow $indexGenerated $issued $expires

    $bundleNames = @(
        'schema','manifest_sha256','source_commit','artifact_source_commit',
        'paper_jar','velocity_jar','bungeecord_jar')
    if (-not (Test-ExactProperties $Index.release_bundle $bundleNames) -or
            -not (Test-StringEqual $Index.release_bundle.schema 'MCACE_RELEASE_BUNDLE_V4') -or
            -not (Test-StringEqual $Index.release_bundle.source_commit `
                $artifactSourceCommit) -or
            -not (Test-StringEqual $Index.release_bundle.artifact_source_commit `
                $artifactSourceCommit) -or
            -not (Test-Sha256 $Index.release_bundle.manifest_sha256)) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_RELEASE_BUNDLE_INDEX_INVALID'
    }
    foreach ($jarRole in @('paper_jar','velocity_jar','bungeecord_jar')) {
        $jar = $Index.release_bundle.$jarRole
        if (-not (Test-ExactProperties $jar @('sha256','size_bytes')) -or
                -not (Test-Sha256 $jar.sha256) -or
                -not (Test-JsonInteger $jar.size_bytes) -or [long]$jar.size_bytes -lt 1024) {
            throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_RELEASE_JAR_INDEX_INVALID|$jarRole"
        }
    }
    if (-not (Test-BuildReleaseBundle $ReleaseBundleRoot $RequestedCommit $artifactSourceCommit)) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_PROTECTED_BUNDLE_INVALID'
    }
    $bundleRootAbsolute = ConvertTo-AbsoluteRepoPath $ReleaseBundleRoot
    $bundleSnapshots = [ordered]@{
        manifest=(Read-ProductionAuthorityLockedFileBytes `
            (Join-Path $bundleRootAbsolute 'release-manifest.properties') 64 1048576 `
            'authority-release-manifest')
        paper_jar=(Read-ProductionAuthorityLockedFileBytes `
            (Join-Path $bundleRootAbsolute 'mcace-server-paper.jar') 1024 134217728 `
            'authority-release-paper')
        velocity_jar=(Read-ProductionAuthorityLockedFileBytes `
            (Join-Path $bundleRootAbsolute 'mcace-server-velocity.jar') 1024 134217728 `
            'authority-release-velocity')
        bungeecord_jar=(Read-ProductionAuthorityLockedFileBytes `
            (Join-Path $bundleRootAbsolute 'mcace-server-bungeecord.jar') 1024 134217728 `
            'authority-release-bungeecord')
    }
    # Index.release_bundle.manifest_sha256 identifies the supervised capture bundle at A.
    # Test-BuildReleaseBundle above validates the protected R/A manifest.  Its content hash must
    # differ when source_commit changes from A to R; deployable equivalence is enforced by the
    # three exact JAR comparisons below and the complete protected-bundle validator.
    foreach ($jarRole in @('paper_jar','velocity_jar','bungeecord_jar')) {
        if ([string]$bundleSnapshots[$jarRole].sha256 -cne
                [string]$Index.release_bundle.$jarRole.sha256 -or
                [long]$bundleSnapshots[$jarRole].size_bytes -ne
                    [long]$Index.release_bundle.$jarRole.size_bytes) {
            throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_RELEASE_JAR_MISMATCH|$jarRole"
        }
    }

    $leaf = [IO.Path]::GetFileNameWithoutExtension($IndexRelative)
    if ($leaf -cnotmatch '^server-confirmed-production-[A-Za-z0-9][A-Za-z0-9._-]*$' -or
            $leaf -match '\.\.') {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_INDEX_ID_INVALID'
    }
    $prefix = "$evidenceRootRelative/server-confirmed-production/$leaf"
    $canonicalLeaves = [ordered]@{
        artifact_manifest='artifact-manifest.json'; binding='binding.json'
        capture_supervisor_public_descriptor='capture-supervisor-public-descriptor.json'
        commit='commit.json'; freeze_manifest='freeze-manifest.json'
        issuance_journal='issuance-journal.log'; paper_events='paper-events.jsonl'
        process_ledger='process-ledger.json'; provider_events='provider-events.jsonl'
        proxy_events='proxy-events.jsonl'; raw_capture_manifest='raw-capture-manifest.json'
        raw_frames='raw-frames.jsonl'; report='report.json'
        supervisor_receipt='supervisor-receipt.json'
    }
    $artifactLeaves = [Collections.Generic.List[string]]::new()
    $artifactLeafSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($artifactRole in $artifactRoles) {
        $descriptor = $Index.packaged_artifacts.$artifactRole
        if (-not (Test-ExactProperties $descriptor @('path','sha256','size_bytes')) -or
                -not (Test-Sha256 $descriptor.sha256) -or
                -not (Test-JsonInteger $descriptor.size_bytes) -or
                [long]$descriptor.size_bytes -le 0 -or
                -not ([string]$descriptor.path).StartsWith(
                    "$prefix/artifacts/", [StringComparison]::Ordinal)) {
            throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_ARTIFACT_DESCRIPTOR_INVALID|$artifactRole"
        }
        $artifactLeaf = ([string]$descriptor.path).Substring(
            ("$prefix/artifacts/").Length)
        if ($artifactLeaf -cnotmatch '^[A-Za-z0-9._-]+\.(?:jar|bin)$' -or
                -not $artifactLeafSet.Add($artifactLeaf)) {
            throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_ARTIFACT_DESCRIPTOR_PATH_INVALID|$artifactRole"
        }
        $artifactLeaves.Add($artifactLeaf)
    }
    $directoryState = Assert-ProductionAuthorityExactDirectory $prefix `
        @($canonicalLeaves.Values) @($artifactLeaves.ToArray())
    $rootSnapshots = [ordered]@{}
    foreach ($entry in $canonicalLeaves.GetEnumerator()) {
        $role = [string]$entry.Key; $fileLeaf = [string]$entry.Value
        $rootSnapshots[$role] = Read-ProductionAuthorityDescriptor `
            $Index.canonical_evidence.$role "$prefix/$fileLeaf" $prefix 20971520 `
            "authority-$role"
    }
    $artifactSnapshots = [ordered]@{}
    foreach ($artifactRole in $artifactRoles) {
        $descriptor = $Index.packaged_artifacts.$artifactRole
        $artifactSnapshots[$artifactRole] = Read-ProductionAuthorityDescriptor `
            $descriptor ([string]$descriptor.path) "$prefix/artifacts" 134217728 `
            "authority-artifact-$artifactRole"
    }

    $jsonDocuments = [ordered]@{}
    foreach ($role in @('artifact_manifest','binding',
            'capture_supervisor_public_descriptor','commit','freeze_manifest',
            'process_ledger','raw_capture_manifest','report','supervisor_receipt')) {
        $bytes = [byte[]]$rootSnapshots[$role].bytes
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and
                $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_UTF8_BOM_REJECTED|$role"
        }
        $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        if ($raw.Contains("`r")) {
            throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_NONCANONICAL_NEWLINE|$role"
        }
        $jsonDocuments[$role] = ConvertFrom-StrictJsonRaw $raw
    }
    $report = $jsonDocuments.report
    $binding = $jsonDocuments.binding
    $commit = $jsonDocuments.commit
    $artifactManifest = $jsonDocuments.artifact_manifest
    if (-not (Test-StringEqual $report.schema `
                'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_REPORT_V4') -or
            -not (Test-StringEqual $binding.schema `
                'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_BINDING_V4') -or
            -not (Test-StringEqual $commit.schema `
                'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_COMMIT_V4') -or
            -not (Test-False $report.release_eligible) -or
            -not (Test-False $binding.release_eligible) -or
            -not (Test-False $commit.release_eligible) -or
            -not (Test-True $report.passed) -or -not (Test-True $binding.passed) -or
            -not (Test-True $commit.committed) -or
            -not (Test-StringEqual $report.source_commit $artifactSourceCommit) -or
            -not (Test-StringEqual $report.artifact_source_commit $artifactSourceCommit) -or
            -not (Test-StringEqual $report.capture_id ([string]$Index.capture_id)) -or
            -not (Test-StringEqual $report.operation_attempt_id `
                ([string]$Index.operation_attempt_id)) -or
            -not (Test-StringEqual $report.selected_proxy ([string]$Index.selected_proxy)) -or
            -not (Test-StringEqual $report.action_ceiling 'MONITOR') -or
            -not (Test-True $report.server_confirmed_only) -or
            -not (Test-True $report.independent_supervisor_signature_verified) -or
            -not (Test-False $report.fixture) -or
            -not (Test-True $report.cleanup_all_zero) -or
            -not (Test-JsonInteger $report.automatic_action_count) -or
            [long]$report.automatic_action_count -ne 0) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_REPORT_INDEX_BINDING_INVALID'
    }
    foreach ($hashName in @(
            'supervisor_descriptor_sha256','supervisor_key_id_sha256',
            'supervisor_receipt_sha256','raw_evidence_root_sha256','raw_frame_set_sha256',
            'provider_evidence_commitment_sha256','profile_sha256','topology_sha256')) {
        if ([string]$report.$hashName -cne [string]$Index.$hashName) {
            throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_REPORT_HASH_BINDING_INVALID|$hashName"
        }
    }
    $reportGenerated = ConvertTo-ProductionAuthorityEvidenceTime $report.generated_at `
        'report-generated-at'
    if ($reportGenerated.Ticks -ne $indexGenerated.Ticks) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_INDEX_REPORT_TIME_MISMATCH'
    }
    if ([string]$report.paper_jar_sha256 -cne
            [string]$Index.release_bundle.paper_jar.sha256 -or
            [string]$report.velocity_jar_sha256 -cne
                [string]$Index.release_bundle.velocity_jar.sha256 -or
            [string]$report.bungeecord_jar_sha256 -cne
                [string]$Index.release_bundle.bungeecord_jar.sha256) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_REPORT_RELEASE_JAR_BINDING_INVALID'
    }

    foreach ($artifactRole in $artifactRoles) {
        $manifestEntry = $artifactManifest.$artifactRole
        $descriptor = $Index.packaged_artifacts.$artifactRole
        if ($null -eq $manifestEntry -or
                [string]$descriptor.path -cne
                    "$prefix/$([string]$manifestEntry.relative_path)" -or
                [string]$descriptor.sha256 -cne [string]$manifestEntry.sha256 -or
                [long]$descriptor.size_bytes -ne [long]$manifestEntry.size_bytes) {
            throw "MCACE_RELEASE_PRODUCTION_AUTHORITY_ARTIFACT_MANIFEST_BINDING_INVALID|$artifactRole"
        }
    }

    $receiptOuter = $jsonDocuments.supervisor_receipt
    if (-not (Test-ExactProperties $receiptOuter @(
            'schema','signed_payload_base64','signed_payload_sha256','signature_base64')) -or
            -not (Test-StringEqual $receiptOuter.schema `
                'MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_V1')) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_INVALID'
    }
    try {
        [byte[]]$payloadBytes = [Convert]::FromBase64String(
            [string]$receiptOuter.signed_payload_base64)
    } catch {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_RECEIPT_PAYLOAD_BASE64_INVALID'
    }
    if ([Convert]::ToBase64String($payloadBytes) -cne
            [string]$receiptOuter.signed_payload_base64 -or
            (Get-BytesSha256 $payloadBytes) -cne
                [string]$receiptOuter.signed_payload_sha256) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_RECEIPT_PAYLOAD_HASH_INVALID'
    }
    $payloadRaw = [Text.UTF8Encoding]::new($false, $true).GetString($payloadBytes)
    $payload = ConvertFrom-StrictJsonRaw $payloadRaw
    try {
        [byte[]]$challenge = [Convert]::FromBase64String(
            [string]$payload.challenge_nonce_base64)
    } catch {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_RECEIPT_CHALLENGE_INVALID'
    }
    if ($challenge.Length -ne 32 -or
            [Convert]::ToBase64String($challenge) -cne
                [string]$payload.challenge_nonce_base64 -or
            (Get-BytesSha256 $challenge) -cne
                [string]$Index.supervisor_challenge_sha256 -or
            [string]$payload.capture_id -cne [string]$Index.capture_id -or
            [string]$payload.operation_attempt_id -cne
                [string]$Index.operation_attempt_id -or
            [string]$payload.signer_key_id_sha256 -cne
                [string]$Index.supervisor_key_id_sha256 -or
            [string]$payload.raw_evidence_root_sha256 -cne
                [string]$Index.raw_evidence_root_sha256 -or
            [string]$payload.raw_frame_set_sha256 -cne
                [string]$Index.raw_frame_set_sha256 -or
            [string]$payload.provider_evidence_commitment_sha256 -cne
                [string]$Index.provider_evidence_commitment_sha256 -or
            [string]$payload.profile_sha256 -cne [string]$Index.profile_sha256 -or
            [string]$payload.topology_sha256 -cne [string]$Index.topology_sha256 -or
            [string]$payload.selected_proxy -cne [string]$Index.selected_proxy -or
            [string]$payload.action_ceiling -cne 'MONITOR' -or
            -not (Test-False $payload.test_fixture) -or
            -not (Test-StringEqual $payload.issued_at ([string]$Index.receipt_issued_at)) -or
            -not (Test-StringEqual $payload.expires_at ([string]$Index.receipt_expires_at))) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_RECEIPT_INDEX_BINDING_INVALID'
    }
    if ([string]$rootSnapshots.capture_supervisor_public_descriptor.sha256 -cne
            [string]$Index.supervisor_descriptor_sha256 -or
            [string]$rootSnapshots.supervisor_receipt.sha256 -cne
                [string]$Index.supervisor_receipt_sha256) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_BINDING_INVALID'
    }

    $approvedDescriptorPin = [Environment]::GetEnvironmentVariable(
        'MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256',
        'Process')
    $approvedOpenSslPath = [Environment]::GetEnvironmentVariable(
        'MCACE_RELEASE_AUTHORITY_OPENSSL_PATH','Process')
    $approvedOpenSslSha256 = [Environment]::GetEnvironmentVariable(
        'MCACE_RELEASE_AUTHORITY_OPENSSL_SHA256','Process')
    if (-not (Test-Sha256 $approvedDescriptorPin) -or
            [string]$approvedDescriptorPin -cne
                [string]$Index.supervisor_descriptor_sha256) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_OOB_DESCRIPTOR_PIN_REQUIRED_OR_MISMATCH'
    }
    if ([string]::IsNullOrWhiteSpace($approvedOpenSslPath) -or
            -not [IO.Path]::IsPathRooted($approvedOpenSslPath) -or
            -not (Test-Sha256 $approvedOpenSslSha256)) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_PINNED_OPENSSL_REQUIRED'
    }

    $validator = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot `
        'production-authority-process-evidence.ps1'))
    Assert-ReleasePathChainNoReparse $validator $true
    if (-not (Test-Path -LiteralPath $validator -PathType Leaf)) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_V4_VALIDATOR_REQUIRED'
    }
    $validatorRelative = 'scripts/production-authority-process-evidence.ps1'
    $trackedValidator = @(& git -C $repoRoot ls-files --error-unmatch --
        $validatorRelative 2>$null)
    if ($LASTEXITCODE -ne 0 -or $trackedValidator.Count -ne 1 -or
            [string]$trackedValidator[0] -cne $validatorRelative) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_V4_VALIDATOR_MUST_BE_TRACKED'
    }
    # The receipt TTL closes the external signing exchange.  Once its immutable
    # package was accepted and committed in-window, later protected verification
    # must remain reproducible instead of expiring the historical evidence.
    $validationOutput = @(& $validator -ValidatePackageRoot $directoryState.absolute `
        -ReleaseBundleRoot $bundleRootAbsolute)
    if (($validationOutput -join "`n") -cnotlike
            '*PRODUCTION_AUTHORITY_V4_PACKAGE_VALIDATION_PASS*') {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_RAW_REVALIDATION_MARKER_MISSING'
    }

    if ((Get-ReleaseNoFollowFileIdentity $directoryState.absolute -Directory) -cne
            [string]$directoryState.root_identity -or
            (Get-ReleaseNoFollowFileIdentity $directoryState.artifact_directory -Directory) -cne
                [string]$directoryState.artifact_identity) {
        throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_DIRECTORY_REPLACED_DURING_VALIDATION'
    }
    $stableSnapshots = @($rootSnapshots.Values) + @($artifactSnapshots.Values) +
        @($bundleSnapshots.Values)
    foreach ($snapshot in $stableSnapshots) {
        $final = Read-ProductionAuthorityLockedFileBytes $snapshot.absolute 1 `
            ([long]$snapshot.maximum_bytes) 'authority-final-stable-reread'
        if ([string]$final.identity -cne [string]$snapshot.identity -or
                [string]$final.sha256 -cne [string]$snapshot.sha256 -or
                [long]$final.size_bytes -ne [long]$snapshot.size_bytes) {
            throw 'MCACE_RELEASE_PRODUCTION_AUTHORITY_FINAL_STABLE_REREAD_MISMATCH'
        }
    }
    Assert-ProductionAuthorityNoSupervisorReplay `
        ([string]$Index.operation_attempt_id) `
        ([string]$Index.supervisor_challenge_sha256) $IndexRelative
    return [pscustomobject]@{
        passed=$true; source_commit=[string]$Index.source_commit
        generated_at=$indexGenerated; evidence=$IndexRelative
    }
}

function Find-ValidatedIndex([string]$Pattern, [string]$Validator, [string]$RequestedCommit) {
    $root = Join-Path $repoRoot $evidenceRootRelative
    $passed = [Collections.Generic.List[object]]::new()
    $errors = [Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $root -PathType Container) {
        foreach ($file in @(Get-ChildItem -LiteralPath $root -File -Filter $Pattern)) {
            $relative = $file.FullName.Substring($repoRoot.Length + 1).Replace('\','/')
            try {
                $doc = Read-StrictRepoJson $relative $evidenceRootRelative $file.Name
                $result = & $Validator $doc.value $relative $RequestedCommit
                if ($null -ne $result -and $result.passed) { [void]$passed.Add($result) }
            } catch { [void]$errors.Add("$relative`: $($_.Exception.Message)") }
        }
    }
    $selected = @($passed | Sort-Object generated_at -Descending | Select-Object -First 1)
    return [pscustomobject]@{
        passed=$selected.Count -eq 1
        selected=$(if ($selected.Count -eq 1) { $selected[0] } else { $null })
        errors=@($errors)
    }
}

function Add-Gate {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$List,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][string]$Evidence,
        [Parameter(Mandatory)][string]$Detail
    )
    [void]$List.Add([pscustomobject][ordered]@{ name=$Name; passed=$Passed; evidence=$Evidence; detail=$Detail })
}

if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $repoRoot 'build/release-readiness/report.json'
}
$ReportPath = ConvertTo-AbsoluteRepoPath $ReportPath
[void][IO.Directory]::CreateDirectory((Split-Path -Parent $ReportPath))

$head = Get-RepoHead
$requestedCommit = if ([string]::IsNullOrWhiteSpace($SourceCommit)) {
    $head
} else {
    $SourceCommit.Trim().ToLowerInvariant()
}
if ($requestedCommit -notmatch '^[0-9a-f]{40}$') { throw 'MCACE_RELEASE_READINESS_SOURCE_COMMIT_INVALID' }
$releaseArtifactSourceCommit = ''
$releaseArtifactSourceError = ''
try { $releaseArtifactSourceCommit = Get-ReleaseArtifactSourceCommit }
catch { $releaseArtifactSourceError = $_.Exception.Message }

$gates = [Collections.Generic.List[object]]::new()

$matrix = Find-ValidatedIndex 'server-version-process-matrix-*.json' 'Assert-MatrixIndex' $requestedCommit
$matrixEvidence = if ($matrix.passed) { [string]$matrix.selected.evidence } else { 'docs/evidence/server-version-process-matrix-*.json' }
$matrixDetail = if ($matrix.passed) {
    'Matrix V4 tracked seven-root-entry package, 12/12 raw/process commitments, protected V4 bundle and three server JAR bindings, externally pinned RSA supervisor receipt, freshness, replay, no-follow, and final stable re-reads verified'
} elseif ($matrix.errors.Count -gt 0) {
    "no valid Matrix V4 externally supervised protected-bundle evidence; rejections: $($matrix.errors -join ' || ')"
} else { 'Matrix V4 externally supervised seven-root-entry package and protected-bundle cross-bindings are missing; V2/V3 remain non-release diagnostics' }
Add-Gate $gates 'server_matrix_exact_source' $matrix.passed $matrixEvidence $matrixDetail

$federation = Find-ValidatedIndex 'federation-gui-handoff-*.json' 'Assert-FederationIndex' $requestedCommit
$federationEvidence = if ($federation.passed) { [string]$federation.selected.evidence } else { 'docs/evidence/federation-gui-handoff-*.json plus tracked native V5 eight-file evidence set, two independently approved out-of-band signer roots, and protected V4 release bundle' }
$guiEvidence = $federationEvidence
$guiDetail = if ($federation.passed) {
    'the Federation V5 independently approved computer-use signer and distinct post-run supervisor signer bind the random challenges, exact process/window/session/attempt, decoded PNG pixels, immutable report/binding, exact release JAR set, and runtime ledger'
} elseif ($federation.errors.Count -gt 0) {
    "Federation V5 cryptographic visible-GUI/post-run evidence rejected: $($federation.errors[-1])"
} else {
    'Federation V5 externally signed computer-use receipt, distinct external post-run receipt, fully decoded PNG, and signed-bound runtime ledger are missing'
}
Add-Gate $gates 'fabric_gui_single_enablement_confirmation' $federation.passed $guiEvidence $guiDetail

$federationDetail = if ($federation.passed) {
    'tracked native V5 eight-file set binds report/binding/commit, signing request, signed GUI receipt, decoded PNG, runtime ledger, and distinct externally signed post-run receipt to exact attempt/peer/connection/subject negatives and the four runtime JAR hashes'
} elseif ($federation.errors.Count -gt 0) {
    "no valid Federation V5 index/native set; last rejection: $($federation.errors[-1])"
} else { 'strict Federation V5 index and native eight-file evidence set are missing' }
Add-Gate $gates 'fabric_federation_real_handoff' $federation.passed $federationEvidence $federationDetail

$vulcan = Find-ValidatedIndex 'vulcan-genuine-event-*.json' 'Assert-VulcanIndex' $requestedCommit
$vulcanEvidence = if ($vulcan.passed) { [string]$vulcan.selected.evidence } else { 'future externally pinned supervisor-signed Vulcan V3 evidence; V2 remains diagnostic-only' }
$vulcanDetail = if ($vulcan.passed) {
    'externally pinned supervisor-signed Vulcan V3 evidence is valid for the exact release artifacts'
} elseif ($vulcan.errors.Count -gt 0) {
    "Vulcan release evidence rejected; last rejection: $($vulcan.errors[-1])"
} else { 'Vulcan V2 diagnostics cannot satisfy release; externally pinned supervisor-signed V3 evidence is missing' }
Add-Gate $gates 'vulcan_genuine_event' $vulcan.passed $vulcanEvidence $vulcanDetail

$authority = Find-ValidatedIndex 'server-confirmed-production-*.json' 'Assert-ProductionAuthorityIndex' $requestedCommit
$authorityEvidence = if ($authority.passed) { [string]$authority.selected.evidence } else { 'docs/evidence/server-confirmed-production-*.json plus tracked V4 14-document raw package, 10 packaged artifacts, external supervisor receipt, and exact V4 release bundle' }
$authorityDetail = if ($authority.passed) {
    'Authority V4 raw capture, two signed frames, genuine Grim/Vulcan provider events, process/journal ledgers, external Ed25519 supervisor receipt, OOB-approved descriptor pin, exact artifact bytes, and protected V4 server JARs were independently revalidated with no-follow locked stable reads and replay rejection'
} elseif ($authority.errors.Count -gt 0) {
    "no valid Authority V4 raw package/index; last rejection: $($authority.errors[-1])"
} else { 'Authority V4 publisher index and its complete externally signed raw package are missing; V1/V3 narratives and prepublication booleans are terminally non-release' }
Add-Gate $gates 'production_server_confirmed_authority' $authority.passed $authorityEvidence $authorityDetail

$releaseBuildPass = -not [string]::IsNullOrWhiteSpace($releaseArtifactSourceCommit) -and
    (Test-ProtectedReleaseCiContext $requestedCommit) -and
    (Test-StringEqual $head $requestedCommit) -and
    (Test-BuildReleaseBundle $ReleaseBundleRoot $requestedCommit $releaseArtifactSourceCommit)
$releaseDetail = if ($releaseBuildPass) {
    'protected main/tag push CI verified the exact V4 bundle, canonical sums, V2 compatibility report, final HEAD, and tracked artifact-source marker'
} elseif (-not [string]::IsNullOrWhiteSpace($releaseArtifactSourceError)) {
    "tracked docs/evidence/release-artifact-source.txt is missing or noncanonical: $releaseArtifactSourceError"
} else {
    'protected main/tag push CI context with exact V4 bundle, V2 compatibility report, and artifact-source marker is required; summary JSON is never accepted'
}
Add-Gate $gates 'protected_exact_release_bundle' $releaseBuildPass "$ReleaseBundleRoot + build/compatibility-contract/report.json + docs/evidence/release-artifact-source.txt in protected CI" $releaseDetail

$clean = @(Get-RepoStatus).Count -eq 0
Add-Gate $gates 'clean_worktree' $clean 'git status --porcelain' $(if ($clean) { 'worktree is clean' } else { 'uncommitted changes are present' })

$ready = @($gates | Where-Object { -not $_.passed }).Count -eq 0
$result = [pscustomobject][ordered]@{
    schema='MCACE_RELEASE_READINESS_V2'
    generated_at=[DateTimeOffset]::Now.ToString('o')
    source_commit=$requestedCommit
    observed_head=$head
    release_ready=$ready
    gates=@($gates)
    blockers=@($gates | Where-Object { -not $_.passed } | ForEach-Object { $_.name })
    interpretation=$(if ($ready) {
        'All native release gates are proven for the requested exact source; protected-main release actions may proceed.'
    } else {
        'Fail-closed: one or more strict native evidence gates are missing, malformed, tampered, or not source-bound.'
    })
}
$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
if ($ready) { Write-Output "MCACE_RELEASE_READINESS_PASS|$ReportPath"; exit 0 }
Write-Output "MCACE_RELEASE_READINESS_BLOCKED|$ReportPath"
$result.blockers | ForEach-Object { Write-Output "MCACE_RELEASE_READINESS_BLOCKER|$_" }
exit 1
