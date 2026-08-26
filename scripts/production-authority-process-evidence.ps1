[CmdletBinding()]
param(
    [ValidateSet('Formal','Fixture')]
    [string]$Mode = 'Formal',

    [string]$CaptureManifestPath,
    [string]$OutputDirectory,

    # Validation-only mode is used by the publisher and release-readiness gate.
    # It never writes to the package being validated.
    [string]$ValidatePackageRoot,
    [switch]$RequireCurrentlyValidReceipt,

    [string]$CaptureSupervisorPublicDescriptorPath,
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedCaptureSupervisorPublicDescriptorSha256,
    [string]$SupervisorSigningRequestPath,
    [string]$SupervisorReceiptPath,
    [ValidateRange(1,840)]
    [int]$SupervisorReceiptWaitSeconds = 60,
    [ValidateRange(3,900)]
    [int]$SupervisorReceiptValiditySeconds = 900,

    [string]$ReleaseBundleRoot,
    [string]$OpenSslPath,
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedOpenSslSha256,

    # V3 compatibility parameters are deliberately non-authoritative.  They
    # cannot promote a report and are rejected in Formal V4 mode.
    [switch]$OperatorAttestsGenuineProviderEvents,
    [switch]$OperatorAttestsNoSyntheticInjection,
    [switch]$OperatorAttestsIsolatedTopology,
    [switch]$OperatorAttestsRealProcessLedger,
    [switch]$OperatorAttestsMonitorOnly,
    [switch]$FixtureOnly,
    [string]$TrustedSupervisorKeySha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $script:PSNativeCommandUseErrorActionPreference = $false
}

$script:RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$script:Utf8Strict = New-Object Text.UTF8Encoding($false, $true)
$script:Utf8NoBom = New-Object Text.UTF8Encoding($false)
$script:MaximumJsonBytes = 4MB
$script:MaximumLedgerBytes = 16MB
$script:MaximumArtifactBytes = 128MB
$script:MaximumToolBytes = 256MB
$script:PackageNames = @(
    'artifact-manifest.json',
    'binding.json',
    'capture-supervisor-public-descriptor.json',
    'commit.json',
    'freeze-manifest.json',
    'issuance-journal.log',
    'paper-events.jsonl',
    'process-ledger.json',
    'provider-events.jsonl',
    'proxy-events.jsonl',
    'raw-capture-manifest.json',
    'raw-frames.jsonl',
    'report.json',
    'supervisor-receipt.json')
$script:PackagedArtifactDirectoryName = 'artifacts'
$script:PackagedArtifactCount = 10
$script:RawRoles = [ordered]@{
    freeze_manifest = 'freeze-manifest.json'
    artifact_manifest = 'artifact-manifest.json'
    provider_events = 'provider-events.jsonl'
    paper_events = 'paper-events.jsonl'
    proxy_events = 'proxy-events.jsonl'
    issuance_journal = 'issuance-journal.log'
    process_ledger = 'process-ledger.json'
    raw_frames = 'raw-frames.jsonl'
}

function Throw-Authority([string]$Code) { throw $Code }

function Test-AuthorityWindows {
    if (Get-Variable IsWindows -ErrorAction SilentlyContinue) { return [bool]$IsWindows }
    return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

function Test-ExactProperties([object]$Value, [string[]]$Expected) {
    if ($null -eq $Value -or $Value -isnot [Management.Automation.PSCustomObject]) { return $false }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    return $actual.Count -eq $wanted.Count -and (($actual -join "`n") -ceq ($wanted -join "`n"))
}

function Test-JsonInteger([object]$Value) {
    return $Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or
        $Value -is [uint16] -or $Value -is [uint32]
}

function Test-JsonString([object]$Value) { return $Value -is [string] }
function Test-JsonArray([object]$Value) { return $Value -is [Array] }

function Assert-JsonBoolean([object]$Value, [string]$Code) {
    if ($Value -isnot [bool]) { Throw-Authority $Code }
}

function Assert-Sha256([object]$Value, [string]$Code) {
    if ($Value -isnot [string] -or [string]$Value -cnotmatch '^[0-9a-f]{64}$') { Throw-Authority $Code }
}

function Assert-Commit([object]$Value, [string]$Code) {
    if ($Value -isnot [string] -or [string]$Value -cnotmatch '^[0-9a-f]{40}$') { Throw-Authority $Code }
}

function Assert-BoundedToken([object]$Value, [string]$Code, [int]$Maximum = 128) {
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Value) -or
            ([string]$Value).Length -gt $Maximum -or
            [string]$Value -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._@/+~-]*$') {
        Throw-Authority $Code
    }
}

function ConvertTo-UtcTime([object]$Value, [string]$Code) {
    if ($Value -isnot [string] -or [string]$Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3,7})?Z$') {
        Throw-Authority $Code
    }
    $parsed = [DateTimeOffset]::MinValue
    # The canonical-shape regex above is intentionally stricter than the
    # framework parser.  TryParse is used here instead of TryParseExact because
    # Windows PowerShell 5.1 binds the DateTimeOffset format-array overload
    # differently from PowerShell 7 on some .NET Framework servicing levels.
    # Assume/adjust UTC is safe because the accepted wire shape requires the
    # literal trailing Z and permits no alternate offset.
    if (-not [DateTimeOffset]::TryParse([string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$parsed)) { Throw-Authority $Code }
    return $parsed.ToUniversalTime()
}

function Get-BytesSha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Test-BytesEqual([byte[]]$Left, [byte[]]$Right) {
    if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) { return $false }
    [int]$difference = 0
    for ($i=0; $i -lt $Left.Length; $i++) { $difference = $difference -bor ($Left[$i] -bxor $Right[$i]) }
    return $difference -eq 0
}

function Initialize-AuthorityFileIdentityApi {
    if (-not (Test-AuthorityWindows) -or ('MCAceAuthorityEvidenceFileIdentityV4' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class MCAceAuthorityEvidenceFileIdentityV4 {
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
            i.FileIndexHigh.ToString("x8") + i.FileIndexLow.ToString("x8") + ":" +
            i.FileSizeHigh.ToString("x8") + i.FileSizeLow.ToString("x8");
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

public static class MCAceAuthorityCrc32CV4 {
    public static uint Compute(byte[] value) {
        uint crc = 0xffffffffu;
        foreach (byte b in value) {
            crc ^= b;
            for (int i = 0; i < 8; i++)
                crc = (crc >> 1) ^ ((crc & 1u) != 0 ? 0x82f63b78u : 0u);
        }
        return ~crc;
    }
}
'@
}

function Assert-PathChainNoReparse([string]$AbsolutePath, [bool]$LeafMustExist) {
    $full = [IO.Path]::GetFullPath($AbsolutePath)
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root)) { Throw-Authority 'PRODUCTION_AUTHORITY_PATH_ROOT_INVALID' }
    $relative = $full.Substring($root.Length)
    # Cast explicitly to char[] so PowerShell does not bind the Object[]
    # overload as a single separator token.  Without this, an intermediate
    # junction could be skipped because the entire relative path was checked
    # as one already-resolved leaf.
    [char[]]$separators = @([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
    $segments = @($relative.Split($separators,[StringSplitOptions]::RemoveEmptyEntries))
    $cursor = $root
    for ($i = 0; $i -lt $segments.Count; $i++) {
        $cursor = Join-Path $cursor $segments[$i]
        if (-not (Test-Path -LiteralPath $cursor)) {
            if ($LeafMustExist -or $i -lt ($segments.Count - 1)) {
                Throw-Authority "PRODUCTION_AUTHORITY_PATH_COMPONENT_MISSING|$cursor"
            }
            return
        }
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($item.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $item.LinkType)) {
            Throw-Authority "PRODUCTION_AUTHORITY_REPARSE_PATH_REJECTED|$cursor"
        }
    }
}

function Get-NoFollowIdentity([string]$Path, [switch]$Directory) {
    if (Test-AuthorityWindows) {
        Initialize-AuthorityFileIdentityApi
        try { return [MCAceAuthorityEvidenceFileIdentityV4]::NoFollow($Path,[bool]$Directory) }
        catch { Throw-Authority "PRODUCTION_AUTHORITY_NOFOLLOW_IDENTITY_FAILED|$($_.Exception.Message)" }
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($item.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $item.LinkType)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_NOFOLLOW_REPARSE_REJECTED'
    }
    return "portable:$($item.FullName):$([long]$item.Length):$($item.LastWriteTimeUtc.Ticks)"
}

function Read-StreamExactly([IO.FileStream]$Stream, [int]$Length, [string]$Role) {
    [byte[]]$bytes = New-Object byte[] $Length
    $offset = 0
    while ($offset -lt $Length) {
        $count = $Stream.Read($bytes,$offset,$Length-$offset)
        if ($count -le 0) { Throw-Authority "PRODUCTION_AUTHORITY_SHORT_READ|$Role" }
        $offset += $count
    }
    if ($Stream.ReadByte() -ne -1) { Throw-Authority "PRODUCTION_AUTHORITY_GROWTH_DURING_READ|$Role" }
    return $bytes
}

function Read-LockedRegularFile([string]$Path, [long]$MaximumBytes, [string]$Role,
        [long]$MinimumBytes = 1L) {
    if ([string]::IsNullOrWhiteSpace($Path)) { Throw-Authority "PRODUCTION_AUTHORITY_FILE_PATH_REQUIRED|$Role" }
    $absolute = [IO.Path]::GetFullPath($Path)
    Assert-PathChainNoReparse $absolute $true
    $item = Get-Item -LiteralPath $absolute -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-Authority "PRODUCTION_AUTHORITY_REGULAR_FILE_REQUIRED|$Role"
    }
    $before = Get-NoFollowIdentity $absolute
    $stream = New-Object IO.FileStream($absolute,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    try {
        $length = [long]$stream.Length
        if ($length -lt $MinimumBytes -or $length -gt $MaximumBytes -or $length -gt [int]::MaxValue) {
            Throw-Authority "PRODUCTION_AUTHORITY_FILE_SIZE_INVALID|$Role|$length"
        }
        if (Test-AuthorityWindows) {
            try { $handleIdentity = [MCAceAuthorityEvidenceFileIdentityV4]::FromHandle($stream.SafeFileHandle) }
            catch { Throw-Authority "PRODUCTION_AUTHORITY_HANDLE_IDENTITY_FAILED|$Role" }
            if ($handleIdentity -cne $before) { Throw-Authority "PRODUCTION_AUTHORITY_HANDLE_IDENTITY_CHANGED|$Role" }
        }
        $first = Read-StreamExactly $stream ([int]$length) "$Role|first"
        $stream.Position = 0L
        $second = Read-StreamExactly $stream ([int]$length) "$Role|second"
        if (-not (Test-BytesEqual $first $second)) {
            Throw-Authority "PRODUCTION_AUTHORITY_LOCKED_DOUBLE_READ_MISMATCH|$Role"
        }
        if ($stream.Length -ne $length) { Throw-Authority "PRODUCTION_AUTHORITY_FILE_CHANGED_DURING_READ|$Role" }
    } finally { $stream.Dispose() }
    Assert-PathChainNoReparse $absolute $true
    if ((Get-NoFollowIdentity $absolute) -cne $before) {
        Throw-Authority "PRODUCTION_AUTHORITY_PATH_IDENTITY_CHANGED|$Role"
    }
    return [pscustomobject]@{
        role=$Role; absolute=$absolute; bytes=[byte[]]$first; size_bytes=[long]$first.Length
        sha256=(Get-BytesSha256 $first); identity=$before
    }
}

function Get-JsonGraphPropertyCount([object]$Value) {
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return 0 }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $properties = @($Value.PSObject.Properties)
        $count = $properties.Count
        foreach ($property in $properties) { $count += Get-JsonGraphPropertyCount $property.Value }
        return $count
    }
    if ($Value -is [Collections.IDictionary]) {
        $count = @($Value.Keys).Count
        foreach ($key in @($Value.Keys)) { $count += Get-JsonGraphPropertyCount $Value[$key] }
        return $count
    }
    if ($Value -is [Collections.IEnumerable]) {
        $count = 0
        foreach ($item in $Value) { $count += Get-JsonGraphPropertyCount $item }
        return $count
    }
    return 0
}

function ConvertFrom-StrictJson([byte[]]$Bytes, [string]$Role) {
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        Throw-Authority "PRODUCTION_AUTHORITY_UTF8_BOM_REJECTED|$Role"
    }
    $raw = $script:Utf8Strict.GetString($Bytes)
    if ($raw.Contains("`r")) { Throw-Authority "PRODUCTION_AUTHORITY_NONCANONICAL_NEWLINE|$Role" }
    $trimmed = $raw.Trim()
    if ($trimmed.Length -lt 2 -or $trimmed[0] -cne '{' -or $trimmed[$trimmed.Length-1] -cne '}') {
        Throw-Authority "PRODUCTION_AUTHORITY_JSON_OBJECT_REQUIRED|$Role"
    }
    $command = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
    if ($command.Parameters.ContainsKey('DateKind')) {
        $value = ConvertFrom-Json -InputObject $raw -DateKind String -ErrorAction Stop
    } else { $value = ConvertFrom-Json -InputObject $raw -ErrorAction Stop }
    $tokens = [regex]::Matches($raw,
        '(?:\{|,)\s*"(?:\\["\\/bfnrt]|\\u[0-9a-fA-F]{4}|[^"\\])*"\s*:',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
    if ($tokens -ne (Get-JsonGraphPropertyCount $value)) {
        Throw-Authority "PRODUCTION_AUTHORITY_DUPLICATE_OR_AMBIGUOUS_PROPERTY|$Role"
    }
    return [pscustomobject]@{ value=$value; raw=$raw }
}

function Read-JsonDocument([string]$Path, [string]$Role, [long]$Maximum = 0L) {
    if ($Maximum -le 0) { $Maximum = $script:MaximumJsonBytes }
    $snapshot = Read-LockedRegularFile $Path $Maximum $Role
    $parsed = ConvertFrom-StrictJson $snapshot.bytes $Role
    $snapshot | Add-Member NoteProperty value $parsed.value
    $snapshot | Add-Member NoteProperty raw $parsed.raw
    return $snapshot
}

function Read-JsonLinesDocument([string]$Path, [string]$Role, [int]$MaximumLines = 100000) {
    $snapshot = Read-LockedRegularFile $Path $script:MaximumLedgerBytes $Role
    if ($snapshot.bytes.Length -ge 3 -and $snapshot.bytes[0] -eq 0xEF -and
            $snapshot.bytes[1] -eq 0xBB -and $snapshot.bytes[2] -eq 0xBF) {
        Throw-Authority "PRODUCTION_AUTHORITY_UTF8_BOM_REJECTED|$Role"
    }
    $raw = $script:Utf8Strict.GetString($snapshot.bytes)
    if ($raw.Contains("`r") -or -not $raw.EndsWith("`n")) {
        Throw-Authority "PRODUCTION_AUTHORITY_JSONL_ENCODING_INVALID|$Role"
    }
    $lines = @($raw.TrimEnd("`n") -split "`n")
    if ($lines.Count -lt 1 -or $lines.Count -gt $MaximumLines -or @($lines | Where-Object { $_.Length -eq 0 }).Count -gt 0) {
        Throw-Authority "PRODUCTION_AUTHORITY_JSONL_LINE_COUNT_INVALID|$Role"
    }
    $records = New-Object 'Collections.Generic.List[object]'
    foreach ($line in $lines) {
        $recordBytes = $script:Utf8NoBom.GetBytes($line)
        $records.Add((ConvertFrom-StrictJson $recordBytes "$Role|line").value)
    }
    $snapshot | Add-Member NoteProperty records @($records.ToArray())
    $snapshot | Add-Member NoteProperty raw $raw
    return $snapshot
}

function ConvertFrom-StrictBase64([object]$Value, [int]$Minimum, [int]$Maximum, [string]$Code) {
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Value)) { Throw-Authority $Code }
    try { [byte[]]$bytes = [Convert]::FromBase64String([string]$Value) }
    catch { Throw-Authority $Code }
    if ($bytes.Length -lt $Minimum -or $bytes.Length -gt $Maximum -or
            [Convert]::ToBase64String($bytes) -cne [string]$Value) { Throw-Authority $Code }
    return $bytes
}

function Add-BigEndianInt32([IO.Stream]$Stream, [long]$Value) {
    [byte[]]$bytes = [BitConverter]::GetBytes([uint32]$Value)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    $Stream.Write($bytes,0,4)
}

function Add-BigEndianInt64([IO.Stream]$Stream, [long]$Value) {
    [byte[]]$bytes = [BitConverter]::GetBytes([int64]$Value)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    $Stream.Write($bytes,0,8)
}

function Add-CanonicalText([IO.Stream]$Stream, [string]$Value) {
    [byte[]]$bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    Add-BigEndianInt32 $Stream $bytes.Length
    $Stream.Write($bytes,0,$bytes.Length)
}

function Get-ProviderEvidenceCommitment([string]$ProfileSha256, [object[]]$Providers) {
    Assert-Sha256 $ProfileSha256 'PRODUCTION_AUTHORITY_PROFILE_SHA_INVALID'
    $stream = New-Object IO.MemoryStream
    try {
        Add-CanonicalText $stream 'mcace/server-authority/provider-profile/v1'
        Add-CanonicalText $stream $ProfileSha256
        $ordered = @($Providers | Sort-Object @{Expression={ [string]$_.provider_id }},@{Expression={ [string]$_.trust_domain_id }})
        Add-BigEndianInt32 $stream $ordered.Count
        foreach ($provider in $ordered) {
            Add-CanonicalText $stream ([string]$provider.trust_domain_id)
            Add-CanonicalText $stream ([string]$provider.provider_id)
            Add-CanonicalText $stream ([string]$provider.provider_version)
            Add-CanonicalText $stream ([string]$provider.stable_check_family)
            Add-BigEndianInt32 $stream ([long]$provider.threshold)
            Add-BigEndianInt32 $stream ([long]$provider.observed_count)
            Add-BigEndianInt64 $stream ([long]$provider.window_started_at_epoch_ms)
            Add-BigEndianInt64 $stream ([long]$provider.window_ended_at_epoch_ms)
        }
        return Get-BytesSha256 $stream.ToArray()
    } finally { $stream.Dispose() }
}

function Get-GrantCommitment([byte[]]$Payload) {
    $stream = New-Object IO.MemoryStream
    try {
        Add-CanonicalText $stream 'mcace/backend-authority/grant/v1'
        Add-BigEndianInt32 $stream $Payload.Length
        $stream.Write($Payload,0,$Payload.Length)
        return Get-BytesSha256 $stream.ToArray()
    } finally { $stream.Dispose() }
}

function Get-RawEvidenceRoot([object]$CaptureDocument, [hashtable]$RawDocuments) {
    $stream = New-Object IO.MemoryStream
    try {
        Add-CanonicalText $stream 'mcace/production-authority/ordered-raw-set/v1'
        Add-CanonicalText $stream ([string]$CaptureDocument.sha256)
        Add-BigEndianInt64 $stream ([long]$CaptureDocument.size_bytes)
        Add-BigEndianInt32 $stream $script:RawRoles.Count
        foreach ($entry in $script:RawRoles.GetEnumerator()) {
            $doc = $RawDocuments[[string]$entry.Key]
            Add-CanonicalText $stream ([string]$entry.Key)
            Add-CanonicalText $stream ([string]$entry.Value)
            Add-CanonicalText $stream ([string]$doc.sha256)
            Add-BigEndianInt64 $stream ([long]$doc.size_bytes)
        }
        return Get-BytesSha256 $stream.ToArray()
    } finally { $stream.Dispose() }
}

function ConvertTo-VarintBytes([uint64]$Value) {
    $list = New-Object 'Collections.Generic.List[byte]'
    do {
        $next = [byte]($Value -band 0x7f)
        $Value = $Value -shr 7
        if ($Value -ne 0) { $next = [byte]($next -bor 0x80) }
        $list.Add($next)
    } while ($Value -ne 0)
    return [byte[]]$list.ToArray()
}

function Read-ProtoVarint([byte[]]$Bytes, [int]$Offset, [string]$Role) {
    [uint64]$value = 0
    $shift = 0
    $start = $Offset
    while ($Offset -lt $Bytes.Length -and $shift -le 63) {
        [byte]$current = $Bytes[$Offset++]
        $value = $value -bor ([uint64]($current -band 0x7f) -shl $shift)
        if (($current -band 0x80) -eq 0) {
            [byte[]]$canonical = ConvertTo-VarintBytes $value
            if ($canonical.Length -ne ($Offset-$start)) { Throw-Authority "PRODUCTION_AUTHORITY_PROTO_NONCANONICAL_VARINT|$Role" }
            return [pscustomobject]@{ value=$value; next=$Offset }
        }
        $shift += 7
    }
    Throw-Authority "PRODUCTION_AUTHORITY_PROTO_VARINT_INVALID|$Role"
}

function Read-ProtoMessage([byte[]]$Bytes, [string]$Role) {
    $fields = New-Object 'Collections.Generic.List[object]'
    $offset = 0
    while ($offset -lt $Bytes.Length) {
        $tag = Read-ProtoVarint $Bytes $offset "$Role|tag"
        $offset = [int]$tag.next
        $number = [int]([uint64]$tag.value -shr 3)
        $wire = [int]([uint64]$tag.value -band 7)
        if ($number -le 0 -or $wire -cnotin @(0,1,2,5)) { Throw-Authority "PRODUCTION_AUTHORITY_PROTO_FIELD_INVALID|$Role" }
        $value = $null
        switch ($wire) {
            0 {
                $parsed = Read-ProtoVarint $Bytes $offset "$Role|field-$number"
                $offset = [int]$parsed.next; $value = [uint64]$parsed.value
            }
            1 {
                if ($offset + 8 -gt $Bytes.Length) { Throw-Authority "PRODUCTION_AUTHORITY_PROTO_TRUNCATED|$Role" }
                [byte[]]$fixed64Bytes = New-Object byte[] 8
                [Array]::Copy($Bytes,$offset,$fixed64Bytes,0,8)
                $value = $fixed64Bytes
                $offset += 8
            }
            2 {
                $lengthValue = Read-ProtoVarint $Bytes $offset "$Role|length-$number"
                $offset = [int]$lengthValue.next; $length = [long][uint64]$lengthValue.value
                if ($length -lt 0 -or $length -gt 1MB -or $offset + $length -gt $Bytes.Length) {
                    Throw-Authority "PRODUCTION_AUTHORITY_PROTO_LENGTH_INVALID|$Role"
                }
                [byte[]]$lengthDelimitedBytes = New-Object byte[] ([int]$length)
                if ($length -gt 0) { [Array]::Copy($Bytes,$offset,$lengthDelimitedBytes,0,[int]$length) }
                $value = $lengthDelimitedBytes
                $offset += [int]$length
            }
            5 {
                if ($offset + 4 -gt $Bytes.Length) { Throw-Authority "PRODUCTION_AUTHORITY_PROTO_TRUNCATED|$Role" }
                [byte[]]$fixed32Bytes = New-Object byte[] 4
                [Array]::Copy($Bytes,$offset,$fixed32Bytes,0,4)
                $value = $fixed32Bytes
                $offset += 4
            }
        }
        $fields.Add([pscustomobject]@{ number=$number; wire=$wire; value=$value })
    }
    return @($fields.ToArray())
}

function Assert-ProtoFieldSequence([object[]]$Fields, [int[]]$Expected, [string]$Role) {
    $actual = @($Fields | ForEach-Object { [int]$_.number })
    if ($actual.Count -ne $Expected.Count -or (($actual -join ',') -cne ($Expected -join ','))) {
        Throw-Authority "PRODUCTION_AUTHORITY_PROTO_FIELD_SET_INVALID|$Role"
    }
}

function Get-ProtoField([object[]]$Fields, [int]$Number, [int]$Wire, [string]$Role) {
    $matches = @($Fields | Where-Object { [int]$_.number -eq $Number })
    if ($matches.Count -ne 1 -or [int]$matches[0].wire -ne $Wire) {
        Throw-Authority "PRODUCTION_AUTHORITY_PROTO_FIELD_REQUIRED|$Role|$Number"
    }
    return $matches[0].value
}

function Get-ProtoText([object[]]$Fields, [int]$Number, [string]$Role) {
    [byte[]]$bytes = Get-ProtoField $Fields $Number 2 $Role
    $text = $script:Utf8Strict.GetString($bytes)
    Assert-BoundedToken $text "PRODUCTION_AUTHORITY_PROTO_TEXT_INVALID|$Role|$Number" 128
    return $text
}

function Get-ProtoUInt64([object[]]$Fields, [int]$Number, [string]$Role) {
    return [uint64](Get-ProtoField $Fields $Number 0 $Role)
}

function Get-Fixed32LittleEndian([byte[]]$Bytes) {
    if ($Bytes.Length -ne 4) { Throw-Authority 'PRODUCTION_AUTHORITY_FIXED32_INVALID' }
    if (-not [BitConverter]::IsLittleEndian) { [Array]::Reverse($Bytes) }
    return [BitConverter]::ToUInt32($Bytes,0)
}

function Get-EnvelopeFacts([byte[]]$Frame, [string]$Role) {
    $envelope = Read-ProtoMessage $Frame "$Role|envelope"
    Assert-ProtoFieldSequence $envelope @(1,2,3) "$Role|envelope"
    [byte[]]$headerBytes = Get-ProtoField $envelope 1 2 "$Role|envelope"
    [byte[]]$payload = Get-ProtoField $envelope 2 2 "$Role|envelope"
    [byte[]]$signature = Get-ProtoField $envelope 3 2 "$Role|envelope"
    if ($signature.Length -ne 64) { Throw-Authority "PRODUCTION_AUTHORITY_ED25519_SIGNATURE_SIZE_INVALID|$Role" }
    $header = Read-ProtoMessage $headerBytes "$Role|header"
    Assert-ProtoFieldSequence $header @(1,2,3,4,5,6,7) "$Role|header"
    $protocol = [long](Get-ProtoUInt64 $header 1 "$Role|header")
    $packet = [long](Get-ProtoUInt64 $header 2 "$Role|header")
    $session = Get-ProtoText $header 3 "$Role|header"
    $timestamp = [long](Get-ProtoUInt64 $header 4 "$Role|header")
    [byte[]]$nonce = Get-ProtoField $header 5 2 "$Role|header"
    $payloadLength = [long](Get-ProtoUInt64 $header 6 "$Role|header")
    $crc = Get-Fixed32LittleEndian ([byte[]](Get-ProtoField $header 7 5 "$Role|header"))
    Initialize-AuthorityFileIdentityApi
    $computedCrc = [MCAceAuthorityCrc32CV4]::Compute($payload)
    if ($protocol -ne 1 -or $packet -cnotin @(21,22) -or $nonce.Length -ne 32 -or
            $payloadLength -ne $payload.Length -or $crc -ne $computedCrc) {
        Throw-Authority "PRODUCTION_AUTHORITY_ENVELOPE_HEADER_INVALID|$Role"
    }
    $stream = New-Object IO.MemoryStream
    try {
        Add-BigEndianInt32 $stream $headerBytes.Length
        $stream.Write($headerBytes,0,$headerBytes.Length)
        $stream.Write($payload,0,$payload.Length)
        [byte[]]$signingBytes = $stream.ToArray()
    } finally { $stream.Dispose() }
    return [pscustomobject]@{
        packet_type=$packet; session_id=$session; timestamp_epoch_ms=$timestamp
        nonce=$nonce; payload=$payload; signature=$signature; signing_bytes=$signingBytes
        header_bytes=$headerBytes
    }
}

function Get-GrantFacts([byte[]]$Payload) {
    $fields = Read-ProtoMessage $Payload 'grant-payload'
    Assert-ProtoFieldSequence $fields @(1,2,3,4,5,6,7,8,9,10,11,12) 'grant-payload'
    [byte[]]$binding = Get-ProtoField $fields 7 2 'grant-payload'
    [byte[]]$challenge = Get-ProtoField $fields 12 2 'grant-payload'
    if ($binding.Length -ne 32 -or $challenge.Length -ne 32) { Throw-Authority 'PRODUCTION_AUTHORITY_GRANT_BYTE_LENGTH_INVALID' }
    return [pscustomobject]@{
        schema_version=[long](Get-ProtoUInt64 $fields 1 'grant-payload')
        grant_id=(Get-ProtoText $fields 2 'grant-payload')
        proxy_instance_id=(Get-ProtoText $fields 3 'grant-payload')
        backend_instance_id=(Get-ProtoText $fields 4 'grant-payload')
        player_uuid=(Get-ProtoText $fields 5 'grant-payload')
        authenticated_session_id=(Get-ProtoText $fields 6 'grant-payload')
        physical_login_binding=$binding
        admission_transport_sequence=[long](Get-ProtoUInt64 $fields 8 'grant-payload')
        grant_sequence=[long](Get-ProtoUInt64 $fields 9 'grant-payload')
        issued_at_epoch_ms=[long](Get-ProtoUInt64 $fields 10 'grant-payload')
        expires_at_epoch_ms=[long](Get-ProtoUInt64 $fields 11 'grant-payload')
        challenge=$challenge
        commitment_sha256=(Get-GrantCommitment $Payload)
    }
}

function Get-ObservationFacts([byte[]]$Payload) {
    $fields = Read-ProtoMessage $Payload 'observation-payload'
    $sequence = @(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)
    $providerFields = @($fields | Where-Object { [int]$_.number -eq 16 })
    $expected = @($sequence + @(16) * $providerFields.Count)
    Assert-ProtoFieldSequence $fields $expected 'observation-payload'
    if ($providerFields.Count -ne 2) { Throw-Authority 'PRODUCTION_AUTHORITY_OBSERVATION_PROVIDER_COUNT_INVALID' }
    $providers = New-Object 'Collections.Generic.List[object]'
    foreach ($providerField in $providerFields) {
        if ([int]$providerField.wire -ne 2) { Throw-Authority 'PRODUCTION_AUTHORITY_PROVIDER_PROTO_WIRE_INVALID' }
        $provider = Read-ProtoMessage ([byte[]]$providerField.value) 'provider-summary'
        Assert-ProtoFieldSequence $provider @(1,2,3,4,5,6,7,8) 'provider-summary'
        $providers.Add([pscustomobject][ordered]@{
            trust_domain_id=(Get-ProtoText $provider 1 'provider-summary')
            provider_id=(Get-ProtoText $provider 2 'provider-summary')
            provider_version=(Get-ProtoText $provider 3 'provider-summary')
            stable_check_family=(Get-ProtoText $provider 4 'provider-summary')
            threshold=[long](Get-ProtoUInt64 $provider 5 'provider-summary')
            observed_count=[long](Get-ProtoUInt64 $provider 6 'provider-summary')
            window_started_at_epoch_ms=[long](Get-ProtoUInt64 $provider 7 'provider-summary')
            window_ended_at_epoch_ms=[long](Get-ProtoUInt64 $provider 8 'provider-summary')
        })
    }
    [byte[]]$profile = Get-ProtoField $fields 15 2 'observation-payload'
    if ($profile.Length -ne 32) { Throw-Authority 'PRODUCTION_AUTHORITY_OBSERVATION_PROFILE_LENGTH_INVALID' }
    $profileHex = ([BitConverter]::ToString($profile)).Replace('-','').ToLowerInvariant()
    return [pscustomobject]@{
        schema_version=[long](Get-ProtoUInt64 $fields 1 'observation-payload')
        attestation_id=(Get-ProtoText $fields 2 'observation-payload')
        backend_instance_id=(Get-ProtoText $fields 3 'observation-payload')
        backend_key_id_sha256=(([BitConverter]::ToString([byte[]](Get-ProtoField $fields 4 2 'observation-payload'))).Replace('-','').ToLowerInvariant())
        player_uuid=(Get-ProtoText $fields 5 'observation-payload')
        authenticated_session_id=(Get-ProtoText $fields 6 'observation-payload')
        grant_id=(Get-ProtoText $fields 7 'observation-payload')
        grant_commitment_sha256=(([BitConverter]::ToString([byte[]](Get-ProtoField $fields 8 2 'observation-payload'))).Replace('-','').ToLowerInvariant())
        physical_login_binding=[byte[]](Get-ProtoField $fields 9 2 'observation-payload')
        admission_transport_sequence=[long](Get-ProtoUInt64 $fields 10 'observation-payload')
        observation_sequence=[long](Get-ProtoUInt64 $fields 11 'observation-payload')
        observed_at_epoch_ms=[long](Get-ProtoUInt64 $fields 12 'observation-payload')
        issued_at_epoch_ms=[long](Get-ProtoUInt64 $fields 13 'observation-payload')
        expires_at_epoch_ms=[long](Get-ProtoUInt64 $fields 14 'observation-payload')
        authority_profile_sha256=$profileHex
        providers=@($providers.ToArray())
    }
}

function Resolve-TrustedOpenSsl([string]$Requested, [string]$ExpectedSha256) {
    if ([string]::IsNullOrWhiteSpace($Requested) -or -not [IO.Path]::IsPathRooted($Requested)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_OPENSSL_ABSOLUTE_PATH_REQUIRED'
    }
    Assert-Sha256 $ExpectedSha256 'PRODUCTION_AUTHORITY_OPENSSL_EXPECTED_SHA256_REQUIRED'
    $absolute = [IO.Path]::GetFullPath($Requested)
    if ((Test-AuthorityWindows) -and [IO.Path]::GetExtension($absolute) -cne '.exe') {
        Throw-Authority 'PRODUCTION_AUTHORITY_OPENSSL_REGULAR_EXECUTABLE_REQUIRED'
    }
    if ([IO.Path]::GetExtension($absolute) -cin @('.ps1','.cmd','.bat','.com')) {
        Throw-Authority 'PRODUCTION_AUTHORITY_OPENSSL_SCRIPT_SHIM_REJECTED'
    }
    $snapshot = Read-LockedRegularFile $absolute $script:MaximumToolBytes 'openssl-executable' 65536
    if ($snapshot.sha256 -cne $ExpectedSha256.ToLowerInvariant()) {
        Throw-Authority 'PRODUCTION_AUTHORITY_OPENSSL_SHA256_MISMATCH'
    }
    $tool = [pscustomobject]@{ path=$absolute; sha256=$snapshot.sha256; identity=$snapshot.identity }
    $version = Invoke-TrustedOpenSsl $tool @('version') 'version'
    if (($version -join "`n") -cnotmatch '(?m)^OpenSSL\s+3(?:\.|\s)') {
        Throw-Authority 'PRODUCTION_AUTHORITY_OPENSSL_3_REQUIRED'
    }
    return $tool
}

function Assert-TrustedToolStable([object]$Tool, [string]$Stage) {
    $snapshot = Read-LockedRegularFile ([string]$Tool.path) $script:MaximumToolBytes "openssl-$Stage" 65536
    if ($snapshot.sha256 -cne [string]$Tool.sha256 -or $snapshot.identity -cne [string]$Tool.identity) {
        Throw-Authority "PRODUCTION_AUTHORITY_OPENSSL_IDENTITY_CHANGED|$Stage"
    }
}

function Invoke-TrustedOpenSsl([object]$Tool, [string[]]$Arguments, [string]$Operation) {
    Assert-TrustedToolStable $Tool "pre-$Operation"
    $saved = [ordered]@{}
    foreach ($name in @(
            'OPENSSL_CONF','OPENSSL_MODULES','OPENSSL_ENGINES','RANDFILE',
            'LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT')) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name,'Process')
        [Environment]::SetEnvironmentVariable($name,$null,'Process')
    }
    try {
        $oldPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $output = @(& ([string]$Tool.path) @Arguments 2>&1)
            $exit = $LASTEXITCODE
        } finally { $ErrorActionPreference = $oldPreference }
    } finally {
        foreach ($name in $saved.Keys) {
            [Environment]::SetEnvironmentVariable($name,[string]$saved[$name],'Process')
        }
    }
    Assert-TrustedToolStable $Tool "post-$Operation"
    if ($exit -ne 0) { Throw-Authority "PRODUCTION_AUTHORITY_OPENSSL_OPERATION_FAILED|$Operation" }
    return @($output | ForEach-Object { [string]$_ })
}

function Test-Ed25519Signature([object]$Tool, [byte[]]$PublicDer, [byte[]]$Content,
        [byte[]]$Signature, [string]$Role, [string]$ScratchParent) {
    $scratch = Join-Path $ScratchParent ('.mcace-authority-verify-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($scratch) | Out-Null
    Assert-PathChainNoReparse $scratch $true
    try {
        $public = Join-Path $scratch 'public.der'
        $contentPath = Join-Path $scratch 'content.bin'
        $signaturePath = Join-Path $scratch 'signature.bin'
        [IO.File]::WriteAllBytes($public,$PublicDer)
        [IO.File]::WriteAllBytes($contentPath,$Content)
        [IO.File]::WriteAllBytes($signaturePath,$Signature)
        $null = Invoke-TrustedOpenSsl $Tool @('pkeyutl','-verify','-rawin','-pubin',
            '-keyform','DER','-inkey',$public,'-in',$contentPath,'-sigfile',$signaturePath) "verify-$Role"
    } finally {
        if ([IO.Directory]::Exists($scratch)) { [IO.Directory]::Delete($scratch,$true) }
    }
}

function Assert-Descriptor([object]$Descriptor, [object]$Document, [string]$Leaf, [string]$Role) {
    if (-not (Test-ExactProperties $Descriptor @('relative_path','sha256','size_bytes')) -or
            [string]$Descriptor.relative_path -cne $Leaf -or
            [string]$Descriptor.sha256 -cne [string]$Document.sha256 -or
            -not (Test-JsonInteger $Descriptor.size_bytes) -or
            [long]$Descriptor.size_bytes -ne [long]$Document.size_bytes) {
        Throw-Authority "PRODUCTION_AUTHORITY_DESCRIPTOR_MISMATCH|$Role"
    }
}

function Read-RawCaptureSet([string]$CapturePath) {
    $captureDoc = Read-JsonDocument $CapturePath 'raw-capture-manifest'
    $capture = $captureDoc.value
    $captureProperties = @('schema','source_mode','source_commit','artifact_source_commit','capture_id',
        'operation_attempt_id','started_at','completed_at','selected_proxy','operator_session_sha256',
        'supervisor','files')
    if (-not (Test-ExactProperties $capture $captureProperties) -or
            [string]$capture.schema -cne 'MCACE_PRODUCTION_AUTHORITY_RAW_CAPTURE_V4') {
        Throw-Authority 'PRODUCTION_AUTHORITY_RAW_CAPTURE_V4_REQUIRED'
    }
    Assert-Commit $capture.source_commit 'PRODUCTION_AUTHORITY_SOURCE_COMMIT_INVALID'
    Assert-Commit $capture.artifact_source_commit 'PRODUCTION_AUTHORITY_ARTIFACT_SOURCE_COMMIT_INVALID'
    $captureId = [guid]::Empty; $attemptId = [guid]::Empty
    if (-not [guid]::TryParseExact([string]$capture.capture_id,'D',[ref]$captureId) -or
            $captureId.ToString('D') -cne [string]$capture.capture_id -or
            -not [guid]::TryParseExact([string]$capture.operation_attempt_id,'D',[ref]$attemptId) -or
            $attemptId.ToString('D') -cne [string]$capture.operation_attempt_id) {
        Throw-Authority 'PRODUCTION_AUTHORITY_CAPTURE_OR_ATTEMPT_ID_INVALID'
    }
    $started = ConvertTo-UtcTime $capture.started_at 'PRODUCTION_AUTHORITY_CAPTURE_START_INVALID'
    $completed = ConvertTo-UtcTime $capture.completed_at 'PRODUCTION_AUTHORITY_CAPTURE_COMPLETE_INVALID'
    if ($completed -le $started -or ($completed-$started).TotalHours -gt 12) {
        Throw-Authority 'PRODUCTION_AUTHORITY_CAPTURE_TIME_ORDER_INVALID'
    }
    Assert-Sha256 $capture.operator_session_sha256 'PRODUCTION_AUTHORITY_OPERATOR_SESSION_INVALID'
    if ([string]$capture.selected_proxy -cnotin @('velocity','bungeecord')) {
        Throw-Authority 'PRODUCTION_AUTHORITY_SELECTED_PROXY_INVALID'
    }
    $supervisorNames = @('schema','supervisor_instance_id','supervisor_run_id',
        'global_sequence_assignment','event_count','event_chain_root_sha256','fixture')
    if (-not (Test-ExactProperties $capture.supervisor $supervisorNames) -or
            [string]$capture.supervisor.schema -cne 'MCACE_PRODUCTION_AUTHORITY_CAPTURE_SUPERVISOR_V4' -or
            [string]$capture.supervisor.global_sequence_assignment -cne 'SUPERVISOR_MONOTONIC_TOTAL_ORDER' -or
            -not (Test-JsonInteger $capture.supervisor.event_count) -or
            [long]$capture.supervisor.event_count -le 0) {
        Throw-Authority 'PRODUCTION_AUTHORITY_CAPTURE_SUPERVISOR_V4_INVALID'
    }
    Assert-BoundedToken $capture.supervisor.supervisor_instance_id 'PRODUCTION_AUTHORITY_SUPERVISOR_INSTANCE_INVALID'
    $runId = [guid]::Empty
    if (-not [guid]::TryParseExact([string]$capture.supervisor.supervisor_run_id,'D',[ref]$runId)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_SUPERVISOR_RUN_ID_INVALID'
    }
    Assert-Sha256 $capture.supervisor.event_chain_root_sha256 'PRODUCTION_AUTHORITY_EVENT_CHAIN_ROOT_INVALID'
    Assert-JsonBoolean $capture.supervisor.fixture 'PRODUCTION_AUTHORITY_SUPERVISOR_FIXTURE_TYPE_INVALID'
    if (-not (Test-ExactProperties $capture.files @($script:RawRoles.Keys))) {
        Throw-Authority 'PRODUCTION_AUTHORITY_RAW_FILE_DESCRIPTOR_SET_INVALID'
    }
    $root = Split-Path -Parent $captureDoc.absolute
    $rootPrefix = [IO.Path]::GetFullPath($root).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    $documents = @{}
    foreach ($entry in $script:RawRoles.GetEnumerator()) {
        $descriptor = $capture.files.([string]$entry.Key)
        if (-not (Test-ExactProperties $descriptor @('relative_path','sha256','size_bytes')) -or
                [string]$descriptor.relative_path -cne [string]$entry.Value) {
            Throw-Authority "PRODUCTION_AUTHORITY_RAW_DESCRIPTOR_INVALID|$($entry.Key)"
        }
        $path = [IO.Path]::GetFullPath((Join-Path $root ([string]$descriptor.relative_path)))
        if (-not $path.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)) {
            Throw-Authority "PRODUCTION_AUTHORITY_RAW_PATH_ESCAPE_REJECTED|$($entry.Key)"
        }
        $maximum = if ([string]$entry.Key -in @('provider_events','paper_events','proxy_events','raw_frames','issuance_journal')) {
            $script:MaximumLedgerBytes
        } else { $script:MaximumJsonBytes }
        $doc = Read-LockedRegularFile $path $maximum ([string]$entry.Key)
        Assert-Descriptor $descriptor $doc ([string]$entry.Value) ([string]$entry.Key)
        $documents[[string]$entry.Key] = $doc
    }
    return [pscustomobject]@{ capture_document=$captureDoc; capture=$capture; documents=$documents;
        started=$started; completed=$completed; root=$root }
}

function Get-CanonicalProfileSha256([object[]]$Providers, [long]$IndependentDomains,
        [long]$MaximumWindowMs, [long]$CooldownMs) {
    $ordered = @($Providers | Sort-Object { [string]$_.provider_id })
    if ($ordered.Count -ne 2) { Throw-Authority 'PRODUCTION_AUTHORITY_PROFILE_PROVIDER_COUNT_INVALID' }
    $stream = New-Object IO.MemoryStream
    try {
        Add-CanonicalText $stream 'mcace/backend-authority/profile/v1'
        Add-BigEndianInt64 $stream $IndependentDomains
        Add-BigEndianInt64 $stream $MaximumWindowMs
        Add-BigEndianInt64 $stream $CooldownMs
        Add-BigEndianInt64 $stream $ordered.Count
        foreach ($provider in $ordered) {
            Add-CanonicalText $stream ([string]$provider.provider_id)
            Add-CanonicalText $stream ([string]$provider.trust_domain_id)
            Add-CanonicalText $stream ([string]$provider.version)
            Add-CanonicalText $stream ([string]$provider.stable_check_family)
            Add-BigEndianInt64 $stream ([long]$provider.threshold)
        }
        return Get-BytesSha256 $stream.ToArray()
    } finally { $stream.Dispose() }
}

function Get-CanonicalTopologySha256([object]$Topology) {
    $stream = New-Object IO.MemoryStream
    try {
        Add-CanonicalText $stream 'mcace/production-authority/topology/v4'
        foreach ($name in @('selected_proxy_platform','proxy_instance_id','backend_instance_id',
                'registered_backend','paper_role','proxy_activation_constraint')) {
            Add-CanonicalText $stream ([string]$Topology.$name)
        }
        foreach ($name in @('observation_ttl_ms','grant_ttl_ms','journal_quota_bytes')) {
            Add-BigEndianInt64 $stream ([long]$Topology.$name)
        }
        Add-BigEndianInt64 $stream @($Topology.proxy_configuration_targets).Count
        foreach ($target in @($Topology.proxy_configuration_targets)) { Add-CanonicalText $stream ([string]$target) }
        return Get-BytesSha256 $stream.ToArray()
    } finally { $stream.Dispose() }
}

function Assert-PublicDescriptor([object]$Document, [string]$ExpectedSha256, [bool]$Formal) {
    $descriptor = $Document.value
    $names = @('schema','artifact_class','algorithm','key_id_sha256','public_key_der_base64','test_fixture')
    if (-not (Test-ExactProperties $descriptor $names) -or
            [string]$descriptor.schema -cne 'MCACE_PRODUCTION_AUTHORITY_CAPTURE_SUPERVISOR_PUBLIC_DESCRIPTOR_V1' -or
            [string]$descriptor.algorithm -cne 'ED25519' -or
            [string]$descriptor.artifact_class -cnotin @(
                'EXTERNAL_RELEASE_CAPTURE_SUPERVISOR_PUBLIC_ROOT',
                'TEST_CAPTURE_SUPERVISOR_PUBLIC_ROOT_FIXTURE')) {
        Throw-Authority 'PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_INVALID'
    }
    Assert-JsonBoolean $descriptor.test_fixture 'PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_FIXTURE_TYPE_INVALID'
    [byte[]]$publicDer = ConvertFrom-StrictBase64 $descriptor.public_key_der_base64 32 256 `
        'PRODUCTION_AUTHORITY_SUPERVISOR_PUBLIC_KEY_INVALID'
    $keyId = Get-BytesSha256 $publicDer
    if ([string]$descriptor.key_id_sha256 -cne $keyId) {
        Throw-Authority 'PRODUCTION_AUTHORITY_SUPERVISOR_KEY_ID_MISMATCH'
    }
    Assert-Sha256 $ExpectedSha256 'PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_PIN_REQUIRED'
    if ([string]$Document.sha256 -cne $ExpectedSha256.ToLowerInvariant()) {
        Throw-Authority 'PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_PIN_MISMATCH'
    }
    if ($Formal) {
        $approved = [Environment]::GetEnvironmentVariable(
            'MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256','Process')
        if ([string]::IsNullOrWhiteSpace($approved) -or $approved -cnotmatch '^[0-9a-f]{64}$' -or
                $approved -cne $ExpectedSha256.ToLowerInvariant()) {
            Throw-Authority 'PRODUCTION_AUTHORITY_OUT_OF_BAND_APPROVED_PIN_REQUIRED'
        }
        if ([bool]$descriptor.test_fixture -or
                [string]$descriptor.artifact_class -cne 'EXTERNAL_RELEASE_CAPTURE_SUPERVISOR_PUBLIC_ROOT') {
            Throw-Authority 'PRODUCTION_AUTHORITY_FIXTURE_SUPERVISOR_RELEASE_REJECTED'
        }
    }
    return [pscustomobject]@{ public_der=$publicDer; key_id_sha256=$keyId; fixture=[bool]$descriptor.test_fixture }
}

function Assert-FreezeManifest([object]$Document, [object]$Capture, [object]$DescriptorInfo,
        [string]$DescriptorSha256, [bool]$Formal) {
    $freeze = (ConvertFrom-StrictJson $Document.bytes 'freeze-manifest').value
    $top = @('schema_version','artifact_source_commit','action_ceiling','evidence_supervisor',
        'proxy_authority','backend_authority','behavior','profile','topology')
    if (-not (Test-ExactProperties $freeze $top) -or
            [string]$freeze.schema_version -cne 'mcace-production-authority-freeze/v3' -or
            [string]$freeze.artifact_source_commit -cne [string]$Capture.artifact_source_commit -or
            [string]$freeze.action_ceiling -cne 'MONITOR') {
        Throw-Authority 'PRODUCTION_AUTHORITY_FREEZE_V3_INVALID'
    }
    $supervisorNames = @('algorithm','key_id_sha256','public_descriptor_sha256',
        'public_key_descriptor_path','approved_pin_required','private_key_present')
    if (-not (Test-ExactProperties $freeze.evidence_supervisor $supervisorNames) -or
            [string]$freeze.evidence_supervisor.algorithm -cne 'ED25519' -or
            [string]$freeze.evidence_supervisor.key_id_sha256 -cne [string]$DescriptorInfo.key_id_sha256 -or
            [string]$freeze.evidence_supervisor.public_descriptor_sha256 -cne $DescriptorSha256 -or
            [string]$freeze.evidence_supervisor.public_key_descriptor_path -cne
                'evidence-supervisor/capture-supervisor-public-descriptor.json' -or
            $freeze.evidence_supervisor.approved_pin_required -isnot [bool] -or
            -not [bool]$freeze.evidence_supervisor.approved_pin_required -or
            $freeze.evidence_supervisor.private_key_present -isnot [bool] -or
            [bool]$freeze.evidence_supervisor.private_key_present) {
        Throw-Authority 'PRODUCTION_AUTHORITY_FREEZE_SUPERVISOR_INVALID'
    }
    $proxyNames = @('proxy_instance_id','selected_proxy_platform','proxy_identity_key_id_sha256',
        'proxy_public_key_der_base64','paper_public_key_pin_path','selected_proxy_public_key_path')
    $backendNames = @('registered_backend','backend_instance_id','backend_key_id_sha256',
        'backend_public_key_der_base64')
    if (-not (Test-ExactProperties $freeze.proxy_authority $proxyNames) -or
            -not (Test-ExactProperties $freeze.backend_authority $backendNames)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_FREEZE_AUTHORITY_KEYS_INVALID'
    }
    [byte[]]$proxyDer = ConvertFrom-StrictBase64 $freeze.proxy_authority.proxy_public_key_der_base64 32 256 `
        'PRODUCTION_AUTHORITY_PROXY_PUBLIC_KEY_INVALID'
    [byte[]]$backendDer = ConvertFrom-StrictBase64 $freeze.backend_authority.backend_public_key_der_base64 32 256 `
        'PRODUCTION_AUTHORITY_BACKEND_PUBLIC_KEY_INVALID'
    if ((Get-BytesSha256 $proxyDer) -cne [string]$freeze.proxy_authority.proxy_identity_key_id_sha256 -or
            (Get-BytesSha256 $backendDer) -cne [string]$freeze.backend_authority.backend_key_id_sha256 -or
            [string]$freeze.proxy_authority.selected_proxy_platform -cne [string]$Capture.selected_proxy) {
        Throw-Authority 'PRODUCTION_AUTHORITY_FROZEN_KEY_ID_MISMATCH'
    }
    $behaviorNames = @('enabled','adapters')
    if (-not (Test-ExactProperties $freeze.behavior $behaviorNames) -or
            -not (Test-ExactProperties $freeze.behavior.adapters @('grim','vulcan')) -or
            $freeze.behavior.enabled -isnot [bool] -or -not [bool]$freeze.behavior.enabled -or
            $freeze.behavior.adapters.grim -isnot [bool] -or -not [bool]$freeze.behavior.adapters.grim -or
            $freeze.behavior.adapters.vulcan -isnot [bool] -or -not [bool]$freeze.behavior.adapters.vulcan) {
        Throw-Authority 'PRODUCTION_AUTHORITY_BEHAVIOR_ADAPTERS_INVALID'
    }
    $profileNames = @('name','sha256','required_independent_domains','maximum_provider_window_ms',
        'cooldown_ms','providers')
    if (-not (Test-ExactProperties $freeze.profile $profileNames) -or
            -not (Test-JsonInteger $freeze.profile.required_independent_domains) -or
            [long]$freeze.profile.required_independent_domains -ne 2 -or
            -not (Test-JsonInteger $freeze.profile.maximum_provider_window_ms) -or
            [long]$freeze.profile.maximum_provider_window_ms -le 0 -or
            [long]$freeze.profile.maximum_provider_window_ms -gt 30000 -or
            -not (Test-JsonInteger $freeze.profile.cooldown_ms) -or
            [long]$freeze.profile.cooldown_ms -lt 0 -or @($freeze.profile.providers).Count -ne 2) {
        Throw-Authority 'PRODUCTION_AUTHORITY_PROFILE_INVALID'
    }
    foreach ($provider in @($freeze.profile.providers)) {
        if (-not (Test-ExactProperties $provider @('provider_id','trust_domain_id','version',
                'stable_check_family','threshold')) -or
                [string]$provider.provider_id -cnotin @('grim','vulcan') -or
                -not (Test-JsonInteger $provider.threshold) -or [long]$provider.threshold -le 0 -or
                [long]$provider.threshold -gt 256) {
            Throw-Authority 'PRODUCTION_AUTHORITY_PROFILE_PROVIDER_INVALID'
        }
    }
    $recomputedProfile = Get-CanonicalProfileSha256 @($freeze.profile.providers) `
        ([long]$freeze.profile.required_independent_domains) `
        ([long]$freeze.profile.maximum_provider_window_ms) ([long]$freeze.profile.cooldown_ms)
    if ($recomputedProfile -cne [string]$freeze.profile.sha256) {
        Throw-Authority 'PRODUCTION_AUTHORITY_PROFILE_COMMITMENT_MISMATCH'
    }
    $topologyNames = @('selected_proxy_platform','proxy_instance_id','backend_instance_id',
        'registered_backend','observation_ttl_ms','grant_ttl_ms','journal_quota_bytes','paper_role',
        'proxy_configuration_targets','proxy_activation_constraint','sha256')
    if (-not (Test-ExactProperties $freeze.topology $topologyNames) -or
            [string]$freeze.topology.selected_proxy_platform -cne [string]$Capture.selected_proxy -or
            [string]$freeze.topology.proxy_instance_id -cne [string]$freeze.proxy_authority.proxy_instance_id -or
            [string]$freeze.topology.backend_instance_id -cne [string]$freeze.backend_authority.backend_instance_id -or
            [string]$freeze.topology.registered_backend -cne [string]$freeze.backend_authority.registered_backend -or
            -not (Test-JsonInteger $freeze.topology.observation_ttl_ms) -or
            [long]$freeze.topology.observation_ttl_ms -ne 30000 -or
            -not (Test-JsonInteger $freeze.topology.grant_ttl_ms) -or
            [long]$freeze.topology.grant_ttl_ms -ne 30000 -or
            [string]$freeze.topology.paper_role -cne 'signer-and-durable-journal' -or
            ((@($freeze.topology.proxy_configuration_targets) -join ',') -cne 'velocity,bungeecord') -or
            [string]$freeze.topology.proxy_activation_constraint -cne
                'deploy-exactly-one-generated-proxy-configuration') {
        Throw-Authority 'PRODUCTION_AUTHORITY_TOPOLOGY_INVALID'
    }
    $copy = [pscustomobject][ordered]@{}
    foreach ($name in @('selected_proxy_platform','proxy_instance_id','backend_instance_id',
            'registered_backend','observation_ttl_ms','grant_ttl_ms','journal_quota_bytes','paper_role',
            'proxy_configuration_targets','proxy_activation_constraint')) {
        $copy | Add-Member NoteProperty $name $freeze.topology.$name
    }
    if ((Get-CanonicalTopologySha256 $copy) -cne [string]$freeze.topology.sha256) {
        Throw-Authority 'PRODUCTION_AUTHORITY_TOPOLOGY_COMMITMENT_MISMATCH'
    }
    if ($Formal -and [bool]$DescriptorInfo.fixture) { Throw-Authority 'PRODUCTION_AUTHORITY_FIXTURE_FREEZE_REJECTED' }
    return [pscustomobject]@{ value=$freeze; profile_sha256=$recomputedProfile;
        topology_sha256=[string]$freeze.topology.sha256; proxy_public_der=$proxyDer;
        backend_public_der=$backendDer; proxy_key_id=[string]$freeze.proxy_authority.proxy_identity_key_id_sha256;
        backend_key_id=[string]$freeze.backend_authority.backend_key_id_sha256 }
}

function Assert-JarBytes([byte[]]$Bytes, [string]$ExpectedEntry, [string]$Role) {
    if ($Bytes.Length -lt 128 -or $Bytes[0] -ne 0x50 -or $Bytes[1] -ne 0x4b) {
        Throw-Authority "PRODUCTION_AUTHORITY_FAKE_JAR_REJECTED|$Role"
    }
    # Keep helper output out of the caller's pipeline.  An emitted RuntimeType
    # here would turn Read-ReleaseBundle's single result into Object[] and make
    # strict member access fail before any artifact binding is checked.
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue | Out-Null
    $stream = New-Object IO.MemoryStream(,$Bytes)
    $archive = $null
    try {
        $archive = New-Object IO.Compression.ZipArchive($stream,[IO.Compression.ZipArchiveMode]::Read,$false)
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $found = $false
        foreach ($entry in @($archive.Entries)) {
            $name = [string]$entry.FullName
            if ([string]::IsNullOrWhiteSpace($name) -or $name.Contains('\') -or
                    $name.StartsWith('/') -or $name -match '(^|/)\.\.(/|$)' -or
                    -not $seen.Add($name) -or [long]$entry.Length -gt 32MB) {
                Throw-Authority "PRODUCTION_AUTHORITY_JAR_ENTRY_INVALID|$Role"
            }
            if ($name -ceq $ExpectedEntry) { $found = $true }
        }
        if (-not $found) { Throw-Authority "PRODUCTION_AUTHORITY_JAR_MAIN_CLASS_MISSING|$Role" }
    } catch {
        if ($_.Exception.Message -like 'PRODUCTION_AUTHORITY_*') { throw }
        Throw-Authority "PRODUCTION_AUTHORITY_FAKE_JAR_REJECTED|$Role"
    } finally {
        if ($null -ne $archive) { $archive.Dispose() }
        $stream.Dispose()
    }
}

function Read-ArtifactManifest([object]$Document, [string]$CaptureRoot, [object]$Capture,
        [bool]$Formal) {
    $manifest = (ConvertFrom-StrictJson $Document.bytes 'artifact-manifest').value
    $roles = @('java_runtime','minecraft_client','fabric_loader','mcace_client_fabric',
        'paper_server','mcace_server_paper','grim','vulcan','mcace_server_velocity',
        'mcace_server_bungeecord')
    if (-not (Test-ExactProperties $manifest (@('schema','source_commit','artifact_source_commit') + $roles)) -or
            [string]$manifest.schema -cne 'MCACE_PRODUCTION_AUTHORITY_ARTIFACT_MANIFEST_V4' -or
            [string]$manifest.source_commit -cne [string]$Capture.source_commit -or
            [string]$manifest.artifact_source_commit -cne [string]$Capture.artifact_source_commit) {
        Throw-Authority 'PRODUCTION_AUTHORITY_ARTIFACT_MANIFEST_V4_INVALID'
    }
    $rootPrefix = [IO.Path]::GetFullPath($CaptureRoot).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    $artifacts = @{}
    $artifactRelativePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($role in $roles) {
        $entry = $manifest.$role
        $expected = @('relative_path','sha256','size_bytes','version','release_bundle_file')
        if ($role -ceq 'vulcan') { $expected += @('licensed','reviewed','review_sha256') }
        if (-not (Test-ExactProperties $entry $expected) -or
                [string]$entry.relative_path -cnotmatch '^artifacts/[A-Za-z0-9._-]+\.(?:jar|bin)$' -or
                -not (Test-JsonInteger $entry.size_bytes) -or [long]$entry.size_bytes -le 0 -or
                [string]::IsNullOrWhiteSpace([string]$entry.version)) {
            Throw-Authority "PRODUCTION_AUTHORITY_ARTIFACT_ENTRY_INVALID|$role"
        }
        if (-not $artifactRelativePaths.Add([string]$entry.relative_path)) {
            Throw-Authority "PRODUCTION_AUTHORITY_ARTIFACT_PATH_ALIAS_REJECTED|$role"
        }
        Assert-Sha256 $entry.sha256 "PRODUCTION_AUTHORITY_ARTIFACT_HASH_INVALID|$role"
        $path = [IO.Path]::GetFullPath((Join-Path $CaptureRoot ([string]$entry.relative_path)))
        if (-not $path.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)) {
            Throw-Authority "PRODUCTION_AUTHORITY_ARTIFACT_PATH_ESCAPE_REJECTED|$role"
        }
        $doc = Read-LockedRegularFile $path $script:MaximumArtifactBytes "artifact-$role"
        if ($doc.sha256 -cne [string]$entry.sha256 -or $doc.size_bytes -ne [long]$entry.size_bytes) {
            Throw-Authority "PRODUCTION_AUTHORITY_ARTIFACT_BYTES_MISMATCH|$role"
        }
        if ($role -ceq 'vulcan') {
            Assert-JsonBoolean $entry.licensed 'PRODUCTION_AUTHORITY_VULCAN_LICENSED_TYPE_INVALID'
            Assert-JsonBoolean $entry.reviewed 'PRODUCTION_AUTHORITY_VULCAN_REVIEWED_TYPE_INVALID'
            Assert-Sha256 $entry.review_sha256 'PRODUCTION_AUTHORITY_VULCAN_REVIEW_SHA_INVALID'
            if ($Formal -and (-not [bool]$entry.licensed -or -not [bool]$entry.reviewed -or
                    [string]$entry.review_sha256 -cne [string]$entry.sha256)) {
                Throw-Authority 'PRODUCTION_AUTHORITY_LICENSED_VULCAN_REQUIRED'
            }
        }
        $artifacts[$role] = [pscustomobject]@{ entry=$entry; document=$doc }
    }
    return [pscustomobject]@{ value=$manifest; artifacts=$artifacts }
}

function Read-ReleaseBundle([string]$Root, [string]$SourceCommit, [string]$ArtifactCommit) {
    if ([string]::IsNullOrWhiteSpace($Root)) { Throw-Authority 'PRODUCTION_AUTHORITY_RELEASE_BUNDLE_REQUIRED' }
    $absolute = [IO.Path]::GetFullPath($Root)
    Assert-PathChainNoReparse $absolute $true
    if (-not (Test-Path -LiteralPath $absolute -PathType Container)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_RELEASE_BUNDLE_DIRECTORY_REQUIRED'
    }
    $names = @('SHA256SUMS','release-manifest.properties','mcace-client-fabric-1.21.11.jar',
        'mcace-client-fabric-26.1.2.jar','mcace-client-fabric-26.2.jar','mcace-server-velocity.jar',
        'mcace-server-bungeecord.jar','mcace-server-paper.jar')
    $entries = @(Get-ChildItem -LiteralPath $absolute -Force -ErrorAction Stop)
    if ($entries.Count -ne $names.Count -or
            ((@($entries.Name | Sort-Object) -join '|') -cne (($names | Sort-Object) -join '|'))) {
        Throw-Authority 'PRODUCTION_AUTHORITY_RELEASE_BUNDLE_FILE_SET_INVALID'
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($entry.Attributes -band [IO.FileAttributes]::Hidden) -ne 0) {
            Throw-Authority 'PRODUCTION_AUTHORITY_RELEASE_BUNDLE_REGULAR_FILES_REQUIRED'
        }
    }
    $manifestDoc = Read-LockedRegularFile (Join-Path $absolute 'release-manifest.properties') 1MB 'release-manifest'
    $sumsDoc = Read-LockedRegularFile (Join-Path $absolute 'SHA256SUMS') 1MB 'release-sha256sums'
    $manifestRaw = $script:Utf8Strict.GetString($manifestDoc.bytes)
    $sumsRaw = $script:Utf8Strict.GetString($sumsDoc.bytes)
    if ($manifestRaw.Contains("`r") -or -not $manifestRaw.EndsWith("`n") -or
            $sumsRaw.Contains("`r") -or -not $sumsRaw.EndsWith("`n")) {
        Throw-Authority 'PRODUCTION_AUTHORITY_RELEASE_BUNDLE_ENCODING_INVALID'
    }
    $map = [ordered]@{}
    foreach ($line in @($manifestRaw.TrimEnd("`n") -split "`n")) {
        $separator = $line.IndexOf('=')
        if ($separator -lt 1) { Throw-Authority 'PRODUCTION_AUTHORITY_RELEASE_MANIFEST_LINE_INVALID' }
        $key = $line.Substring(0,$separator); $value = $line.Substring($separator+1)
        if ($key -cnotmatch '^[A-Za-z0-9._-]+$' -or $map.Contains($key)) {
            Throw-Authority 'PRODUCTION_AUTHORITY_RELEASE_MANIFEST_KEY_INVALID'
        }
        $map[$key] = $value
    }
    $jarNames = @($names | Where-Object { $_.EndsWith('.jar',[StringComparison]::Ordinal) })
    $manifestNames = @('schema','bundle_profile','release_identity','deployable_count',
        'bundle_entry_count','product_version','source_commit','artifact_source_commit',
        'root_java_version','root_java_specification_version','root_gradle_version',
        'modern_java_version','modern_java_specification_version','modern_gradle_version')
    foreach ($jarName in $jarNames) {
        $manifestKey = $jarName.Remove($jarName.Length-4).Replace('-','_').Replace('.','_')
        $manifestNames += "artifact.$manifestKey.file"
        $manifestNames += "artifact.$manifestKey.sha256"
        if ($jarName.StartsWith('mcace-client-fabric-',[StringComparison]::Ordinal)) {
            $manifestNames += "artifact.$manifestKey.minecraft_version"
            $manifestNames += "artifact.$manifestKey.client_build_id"
        }
    }
    if (-not (Test-ExactProperties ([pscustomobject]$map) $manifestNames) -or
            [string]$map.schema -cne 'MCACE_RELEASE_BUNDLE_V4' -or
            [string]$map.bundle_profile -cne 'RELEASE' -or [string]$map.release_identity -cne 'true' -or
            [string]$map.deployable_count -cne '6' -or [string]$map.bundle_entry_count -cne '8' -or
            [string]$map.source_commit -cne $SourceCommit -or
            [string]$map.artifact_source_commit -cne $ArtifactCommit -or
            [string]$map.product_version -cne '0.0.1') {
        Throw-Authority 'PRODUCTION_AUTHORITY_RELEASE_BUNDLE_MANIFEST_INVALID'
    }
    $sumMap = @{}
    foreach ($line in @($sumsRaw.TrimEnd("`n") -split "`n")) {
        if ($line -cnotmatch '^(?<hash>[0-9a-f]{64})  (?<file>[A-Za-z0-9._-]+)$' -or
                $sumMap.ContainsKey($Matches.file)) { Throw-Authority 'PRODUCTION_AUTHORITY_SHA256SUMS_INVALID' }
        $sumMap[$Matches.file] = $Matches.hash
    }
    if ($sumMap.Count -ne 6) { Throw-Authority 'PRODUCTION_AUTHORITY_SHA256SUMS_COUNT_INVALID' }
    $artifacts = @{}
    foreach ($name in $jarNames) {
        $doc = Read-LockedRegularFile (Join-Path $absolute $name) $script:MaximumArtifactBytes "bundle-$name" 128
        $key = $name.Remove($name.Length-4).Replace('-','_').Replace('.','_')
        if ([string]$map."artifact.$key.file" -cne $name -or
                [string]$map."artifact.$key.sha256" -cne $doc.sha256 -or
                [string]$sumMap[$name] -cne $doc.sha256) {
            Throw-Authority "PRODUCTION_AUTHORITY_RELEASE_BUNDLE_ARTIFACT_MISMATCH|$name"
        }
        if ($name -cmatch '^mcace-client-fabric-(?<target>1\.21\.11|26\.1\.2|26\.2)\.jar$' -and
                ([string]$map."artifact.$key.minecraft_version" -cne $Matches.target -or
                 [string]$map."artifact.$key.client_build_id" -cne
                    "fabric-$($Matches.target)-$ArtifactCommit")) {
            Throw-Authority "PRODUCTION_AUTHORITY_RELEASE_BUNDLE_CLIENT_IDENTITY_INVALID|$name"
        }
        $artifacts[$name] = $doc
    }
    Assert-JarBytes $artifacts['mcace-server-paper.jar'].bytes `
        'com/ellan/mcace/paper/MCAcePaperPlugin.class' 'paper-bundle'
    Assert-JarBytes $artifacts['mcace-server-velocity.jar'].bytes `
        'com/ellan/mcace/velocity/MCAceVelocityPlugin.class' 'velocity-bundle'
    Assert-JarBytes $artifacts['mcace-server-bungeecord.jar'].bytes `
        'com/ellan/mcace/bungeecord/MCAceBungeePlugin.class' 'bungeecord-bundle'
    return [pscustomobject]@{ root=$absolute; manifest=$manifestDoc; sums=$sumsDoc; artifacts=$artifacts;
        source_commit=$SourceCommit; artifact_source_commit=$ArtifactCommit }
}

function Get-EventChainHash([long]$Ordinal, [string]$Previous, [string]$BodySha256) {
    $stream = New-Object IO.MemoryStream
    try {
        Add-CanonicalText $stream 'mcace/production-authority/raw-event-chain/v4'
        Add-BigEndianInt64 $stream $Ordinal
        Add-CanonicalText $stream $Previous
        Add-CanonicalText $stream $BodySha256
        return Get-BytesSha256 $stream.ToArray()
    } finally { $stream.Dispose() }
}

function Read-RawEventRecords([object]$Document, [string]$ExpectedComponent,
        [object]$Capture, [bool]$Formal) {
    $path = [string]$Document.absolute
    $lines = Read-JsonLinesDocument $path "$ExpectedComponent-events"
    if ($lines.sha256 -cne $Document.sha256) {
        Throw-Authority "PRODUCTION_AUTHORITY_EVENT_LEDGER_REPLACED|$ExpectedComponent"
    }
    $records = New-Object 'Collections.Generic.List[object]'
    foreach ($envelope in @($lines.records)) {
        if (-not (Test-ExactProperties $envelope @('schema','ordinal','previous_event_sha256',
                'event_body_base64','event_body_sha256','event_chain_sha256')) -or
                [string]$envelope.schema -cne 'MCACE_PRODUCTION_AUTHORITY_RAW_EVENT_ENVELOPE_V4' -or
                -not (Test-JsonInteger $envelope.ordinal) -or [long]$envelope.ordinal -le 0) {
            Throw-Authority "PRODUCTION_AUTHORITY_RAW_EVENT_ENVELOPE_INVALID|$ExpectedComponent"
        }
        Assert-Sha256 $envelope.previous_event_sha256 'PRODUCTION_AUTHORITY_EVENT_PREVIOUS_HASH_INVALID'
        Assert-Sha256 $envelope.event_body_sha256 'PRODUCTION_AUTHORITY_EVENT_BODY_HASH_INVALID'
        Assert-Sha256 $envelope.event_chain_sha256 'PRODUCTION_AUTHORITY_EVENT_CHAIN_HASH_INVALID'
        [byte[]]$bodyBytes = ConvertFrom-StrictBase64 $envelope.event_body_base64 32 32768 `
            'PRODUCTION_AUTHORITY_EVENT_BODY_BASE64_INVALID'
        if ((Get-BytesSha256 $bodyBytes) -cne [string]$envelope.event_body_sha256 -or
                (Get-EventChainHash ([long]$envelope.ordinal) ([string]$envelope.previous_event_sha256) `
                    ([string]$envelope.event_body_sha256)) -cne [string]$envelope.event_chain_sha256) {
            Throw-Authority "PRODUCTION_AUTHORITY_EVENT_BODY_OR_CHAIN_MISMATCH|$ExpectedComponent"
        }
        $body = (ConvertFrom-StrictJson $bodyBytes "$ExpectedComponent-event-body").value
        $base = @('schema','capture_id','operation_attempt_id','event_id','component','event','outcome',
            'authenticated_session_sha256','profile_sha256','input_frame_sha256','signed_frame_sha256',
            'genuine','synthetic','experimental','fixture','process_incarnation_id')
        $providerExtra = @('provider_id','trust_domain_id','provider_version','stable_check_family',
            'threshold','observed_count','window_started_at_epoch_ms','window_ended_at_epoch_ms')
        $expected = if ($ExpectedComponent -ceq 'provider') { @($base + $providerExtra) } else { $base }
        $schema = if ($ExpectedComponent -ceq 'provider') {
            'MCACE_PRODUCTION_AUTHORITY_PROVIDER_EVENT_V4'
        } else { 'MCACE_PRODUCTION_AUTHORITY_RUNTIME_EVENT_V4' }
        if (-not (Test-ExactProperties $body $expected) -or [string]$body.schema -cne $schema -or
                [string]$body.capture_id -cne [string]$Capture.capture_id -or
                [string]$body.operation_attempt_id -cne [string]$Capture.operation_attempt_id -or
                [string]$body.component -cne $ExpectedComponent) {
            Throw-Authority "PRODUCTION_AUTHORITY_EVENT_BODY_INVALID|$ExpectedComponent"
        }
        foreach ($name in @('authenticated_session_sha256','profile_sha256','input_frame_sha256',
                'signed_frame_sha256')) { Assert-Sha256 $body.$name "PRODUCTION_AUTHORITY_EVENT_HASH_INVALID|$name" }
        Assert-BoundedToken $body.event_id 'PRODUCTION_AUTHORITY_EVENT_ID_INVALID'
        Assert-BoundedToken $body.event 'PRODUCTION_AUTHORITY_EVENT_NAME_INVALID'
        Assert-BoundedToken $body.outcome 'PRODUCTION_AUTHORITY_EVENT_OUTCOME_INVALID'
        Assert-BoundedToken $body.process_incarnation_id 'PRODUCTION_AUTHORITY_EVENT_PROCESS_INCARCERATION_INVALID'
        foreach ($flag in @('genuine','synthetic','experimental','fixture')) {
            Assert-JsonBoolean $body.$flag "PRODUCTION_AUTHORITY_EVENT_FLAG_TYPE_INVALID|$flag"
        }
        if ($Formal -and (-not [bool]$body.genuine -or [bool]$body.synthetic -or
                [bool]$body.experimental -or [bool]$body.fixture)) {
            Throw-Authority "PRODUCTION_AUTHORITY_NON_GENUINE_EVENT_REJECTED|$ExpectedComponent"
        }
        if ($ExpectedComponent -ceq 'provider') {
            if ([string]$body.event -cne 'PROVIDER_ELIGIBLE' -or [string]$body.outcome -cne 'ELIGIBLE' -or
                    [string]$body.provider_id -cnotin @('grim','vulcan') -or
                    -not (Test-JsonInteger $body.threshold) -or [long]$body.threshold -le 0 -or
                    -not (Test-JsonInteger $body.observed_count) -or
                    [long]$body.observed_count -lt [long]$body.threshold -or
                    -not (Test-JsonInteger $body.window_started_at_epoch_ms) -or
                    -not (Test-JsonInteger $body.window_ended_at_epoch_ms) -or
                    [long]$body.window_ended_at_epoch_ms -lt [long]$body.window_started_at_epoch_ms) {
                Throw-Authority 'PRODUCTION_AUTHORITY_PROVIDER_EVENT_SEMANTICS_INVALID'
            }
        }
        $records.Add([pscustomobject]@{ ordinal=[long]$envelope.ordinal; previous=[string]$envelope.previous_event_sha256;
            chain=[string]$envelope.event_chain_sha256; body=$body; body_bytes=$bodyBytes })
    }
    return @($records.ToArray())
}

function Assert-GlobalEventChain([object[]]$Records, [object]$Supervisor) {
    $ordered = @($Records | Sort-Object { [long]$_.ordinal })
    if ($ordered.Count -ne [long]$Supervisor.event_count) {
        Throw-Authority 'PRODUCTION_AUTHORITY_EVENT_COUNT_MISMATCH'
    }
    $previous = '0' * 64
    $seenOrdinals = [Collections.Generic.HashSet[long]]::new()
    $seenIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for ($i=0; $i -lt $ordered.Count; $i++) {
        $record = $ordered[$i]
        if ([long]$record.ordinal -ne ($i+1) -or -not $seenOrdinals.Add([long]$record.ordinal) -or
                [string]$record.previous -cne $previous -or
                -not $seenIds.Add([string]$record.body.event_id)) {
            Throw-Authority 'PRODUCTION_AUTHORITY_GLOBAL_EVENT_CHAIN_INVALID'
        }
        $previous = [string]$record.chain
    }
    if ($previous -cne [string]$Supervisor.event_chain_root_sha256) {
        Throw-Authority 'PRODUCTION_AUTHORITY_GLOBAL_EVENT_CHAIN_ROOT_MISMATCH'
    }
}

function Read-RawFrames([object]$Document, [object]$Capture, [object]$FreezeInfo,
        [object]$Tool, [string]$ScratchParent, [bool]$Formal) {
    $lines = Read-JsonLinesDocument $Document.absolute 'raw-frames' 64
    if ($lines.sha256 -cne $Document.sha256) { Throw-Authority 'PRODUCTION_AUTHORITY_RAW_FRAMES_REPLACED' }
    if (@($lines.records).Count -ne 2) { Throw-Authority 'PRODUCTION_AUTHORITY_EXACT_GRANT_AND_OBSERVATION_REQUIRED' }
    $facts = @{}
    $nonces = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for ($i=0; $i -lt @($lines.records).Count; $i++) {
        $record = @($lines.records)[$i]
        $names = @('schema','ordinal','frame_type','operation_attempt_id','authenticated_session_sha256',
            'key_id_sha256','input_frame_base64','input_frame_sha256','signed_frame_base64',
            'signed_frame_sha256','genuine','synthetic','experimental','fixture')
        if (-not (Test-ExactProperties $record $names) -or
                [string]$record.schema -cne 'MCACE_PRODUCTION_AUTHORITY_RAW_SIGNED_FRAME_V1' -or
                -not (Test-JsonInteger $record.ordinal) -or [long]$record.ordinal -ne ($i+1) -or
                [string]$record.operation_attempt_id -cne [string]$Capture.operation_attempt_id -or
                [string]$record.frame_type -cnotin @('BACKEND_AUTHORITY_GRANT','SERVER_AUTHORITY_OBSERVATION')) {
            Throw-Authority 'PRODUCTION_AUTHORITY_RAW_FRAME_RECORD_INVALID'
        }
        foreach ($name in @('authenticated_session_sha256','key_id_sha256','input_frame_sha256',
                'signed_frame_sha256')) { Assert-Sha256 $record.$name "PRODUCTION_AUTHORITY_RAW_FRAME_HASH_INVALID|$name" }
        foreach ($flag in @('genuine','synthetic','experimental','fixture')) {
            Assert-JsonBoolean $record.$flag "PRODUCTION_AUTHORITY_RAW_FRAME_FLAG_TYPE_INVALID|$flag"
        }
        if ($Formal -and (-not [bool]$record.genuine -or [bool]$record.synthetic -or
                [bool]$record.experimental -or [bool]$record.fixture)) {
            Throw-Authority 'PRODUCTION_AUTHORITY_RAW_FRAME_FIXTURE_OR_SYNTHETIC_REJECTED'
        }
        [byte[]]$inputBytes = ConvertFrom-StrictBase64 $record.input_frame_base64 8 8192 `
            'PRODUCTION_AUTHORITY_RAW_INPUT_FRAME_BASE64_INVALID'
        [byte[]]$signed = ConvertFrom-StrictBase64 $record.signed_frame_base64 64 16384 `
            'PRODUCTION_AUTHORITY_RAW_SIGNED_FRAME_BASE64_INVALID'
        if ((Get-BytesSha256 $inputBytes) -cne [string]$record.input_frame_sha256 -or
                (Get-BytesSha256 $signed) -cne [string]$record.signed_frame_sha256) {
            Throw-Authority 'PRODUCTION_AUTHORITY_RAW_FRAME_HASH_MISMATCH'
        }
        $envelope = Get-EnvelopeFacts $signed ([string]$record.frame_type)
        if (-not (Test-BytesEqual $inputBytes ([byte[]]$envelope.payload)) -or
                (Get-BytesSha256 ([Text.Encoding]::UTF8.GetBytes([string]$envelope.session_id))) -cne
                    [string]$record.authenticated_session_sha256) {
            Throw-Authority 'PRODUCTION_AUTHORITY_RAW_FRAME_PAYLOAD_OR_SESSION_MISMATCH'
        }
        $nonceHash = Get-BytesSha256 $envelope.nonce
        if (-not $nonces.Add($nonceHash)) { Throw-Authority 'PRODUCTION_AUTHORITY_RAW_FRAME_NONCE_REPLAY' }
        if ([string]$record.frame_type -ceq 'BACKEND_AUTHORITY_GRANT') {
            if ([long]$envelope.packet_type -ne 21 -or [string]$record.key_id_sha256 -cne [string]$FreezeInfo.proxy_key_id) {
                Throw-Authority 'PRODUCTION_AUTHORITY_GRANT_KEY_OR_PACKET_MISMATCH'
            }
            Test-Ed25519Signature $Tool $FreezeInfo.proxy_public_der $envelope.signing_bytes `
                $envelope.signature 'grant-frame' $ScratchParent
            $payloadFacts = Get-GrantFacts $inputBytes
            $publicDer = $FreezeInfo.proxy_public_der
        } else {
            if ([long]$envelope.packet_type -ne 22 -or [string]$record.key_id_sha256 -cne [string]$FreezeInfo.backend_key_id) {
                Throw-Authority 'PRODUCTION_AUTHORITY_OBSERVATION_KEY_OR_PACKET_MISMATCH'
            }
            Test-Ed25519Signature $Tool $FreezeInfo.backend_public_der $envelope.signing_bytes `
                $envelope.signature 'observation-frame' $ScratchParent
            $payloadFacts = Get-ObservationFacts $inputBytes
            $publicDer = $FreezeInfo.backend_public_der
        }
        if ($facts.ContainsKey([string]$record.frame_type)) { Throw-Authority 'PRODUCTION_AUTHORITY_RAW_FRAME_DUPLICATE' }
        $facts[[string]$record.frame_type] = [pscustomobject]@{
            record=$record; envelope=$envelope; payload=$payloadFacts; public_der=$publicDer
        }
    }
    if (-not $facts.ContainsKey('BACKEND_AUTHORITY_GRANT') -or
            -not $facts.ContainsKey('SERVER_AUTHORITY_OBSERVATION')) {
        Throw-Authority 'PRODUCTION_AUTHORITY_EXACT_GRANT_AND_OBSERVATION_REQUIRED'
    }
    $grant = $facts['BACKEND_AUTHORITY_GRANT'].payload
    $observation = $facts['SERVER_AUTHORITY_OBSERVATION'].payload
    if ($grant.schema_version -ne 1 -or $observation.schema_version -ne 1 -or
            $grant.grant_id -cne $observation.grant_id -or
            $grant.backend_instance_id -cne $observation.backend_instance_id -or
            $grant.player_uuid -cne $observation.player_uuid -or
            $grant.authenticated_session_id -cne $observation.authenticated_session_id -or
            $grant.admission_transport_sequence -ne $observation.admission_transport_sequence -or
            $grant.commitment_sha256 -cne $observation.grant_commitment_sha256 -or
            -not (Test-BytesEqual ([byte[]]$grant.physical_login_binding) `
                ([byte[]]$observation.physical_login_binding)) -or
            $grant.proxy_instance_id -cne [string]$FreezeInfo.value.proxy_authority.proxy_instance_id -or
            $grant.backend_instance_id -cne [string]$FreezeInfo.value.backend_authority.backend_instance_id -or
            $observation.backend_key_id_sha256 -cne [string]$FreezeInfo.backend_key_id -or
            $observation.authority_profile_sha256 -cne [string]$FreezeInfo.profile_sha256 -or
            $grant.expires_at_epoch_ms -le $grant.issued_at_epoch_ms -or
            ($grant.expires_at_epoch_ms-$grant.issued_at_epoch_ms) -gt 30000 -or
            $observation.expires_at_epoch_ms -le $observation.issued_at_epoch_ms -or
            ($observation.expires_at_epoch_ms-$observation.issued_at_epoch_ms) -gt 30000) {
        Throw-Authority 'PRODUCTION_AUTHORITY_GRANT_OBSERVATION_LINKAGE_INVALID'
    }
    return [pscustomobject]@{ by_type=$facts; grant=$grant; observation=$observation }
}

function Assert-ProviderEvidence([object[]]$ProviderRecords, [object]$FreezeInfo,
        [object]$FrameFacts) {
    if ($ProviderRecords.Count -ne 2) { Throw-Authority 'PRODUCTION_AUTHORITY_EXACT_TWO_PROVIDER_EVENTS_REQUIRED' }
    $providers = @($ProviderRecords | ForEach-Object { $_.body } | Sort-Object provider_id)
    if ((@($providers.provider_id) -join ',') -cne 'grim,vulcan' -or
            [string]$providers[0].trust_domain_id -ceq [string]$providers[1].trust_domain_id) {
        Throw-Authority 'PRODUCTION_AUTHORITY_INDEPENDENT_PROVIDER_DOMAINS_INVALID'
    }
    $frameRecord = $FrameFacts.by_type['SERVER_AUTHORITY_OBSERVATION'].record
    foreach ($provider in $providers) {
        if ([string]$provider.authenticated_session_sha256 -cne [string]$frameRecord.authenticated_session_sha256 -or
                [string]$provider.profile_sha256 -cne [string]$FreezeInfo.profile_sha256 -or
                [string]$provider.input_frame_sha256 -cne [string]$frameRecord.input_frame_sha256 -or
                [string]$provider.signed_frame_sha256 -cne [string]$frameRecord.signed_frame_sha256) {
            Throw-Authority 'PRODUCTION_AUTHORITY_PROVIDER_EVENT_FRAME_LINKAGE_INVALID'
        }
        $frozen = @($FreezeInfo.value.profile.providers | Where-Object {
            [string]$_.provider_id -ceq [string]$provider.provider_id })
        if ($frozen.Count -ne 1 -or [string]$frozen[0].trust_domain_id -cne [string]$provider.trust_domain_id -or
                [string]$frozen[0].version -cne [string]$provider.provider_version -or
                [string]$frozen[0].stable_check_family -cne [string]$provider.stable_check_family -or
                [long]$frozen[0].threshold -ne [long]$provider.threshold) {
            Throw-Authority 'PRODUCTION_AUTHORITY_PROVIDER_EVENT_FREEZE_MISMATCH'
        }
    }
    $observedProviders = @($FrameFacts.observation.providers | Sort-Object provider_id)
    for ($i=0; $i -lt 2; $i++) {
        foreach ($name in @('provider_id','trust_domain_id','provider_version','stable_check_family',
                'threshold','observed_count','window_started_at_epoch_ms','window_ended_at_epoch_ms')) {
            if ([string]$observedProviders[$i].$name -cne [string]$providers[$i].$name) {
                Throw-Authority "PRODUCTION_AUTHORITY_PROVIDER_FRAME_MISMATCH|$name"
            }
        }
    }
    return Get-ProviderEvidenceCommitment $FreezeInfo.profile_sha256 $providers
}

function Assert-RuntimeEvents([object[]]$PaperRecords, [object[]]$ProxyRecords,
        [object]$FrameFacts, [string]$ProviderCommitment, [object]$FreezeInfo) {
    $grantRecord = $FrameFacts.by_type['BACKEND_AUTHORITY_GRANT'].record
    $observationRecord = $FrameFacts.by_type['SERVER_AUTHORITY_OBSERVATION'].record
    $paperSigned = @($PaperRecords | Where-Object { [string]$_.body.event -ceq 'OBSERVATION_SIGNED' })
    $proxyGrant = @($ProxyRecords | Where-Object { [string]$_.body.event -ceq 'GRANT_SIGNED' })
    $proxyVerified = @($ProxyRecords | Where-Object { [string]$_.body.event -ceq 'OBSERVATION_VERIFIED' })
    if ($paperSigned.Count -ne 1 -or $proxyGrant.Count -ne 1 -or $proxyVerified.Count -ne 1) {
        Throw-Authority 'PRODUCTION_AUTHORITY_RUNTIME_EVENT_SET_INVALID'
    }
    foreach ($record in @($paperSigned[0].body,$proxyVerified[0].body)) {
        if ([string]$record.input_frame_sha256 -cne [string]$observationRecord.input_frame_sha256 -or
                [string]$record.signed_frame_sha256 -cne [string]$observationRecord.signed_frame_sha256 -or
                [string]$record.profile_sha256 -cne [string]$FreezeInfo.profile_sha256) {
            Throw-Authority 'PRODUCTION_AUTHORITY_OBSERVATION_RUNTIME_LINKAGE_INVALID'
        }
    }
    if ([string]$proxyGrant[0].body.input_frame_sha256 -cne [string]$grantRecord.input_frame_sha256 -or
            [string]$proxyGrant[0].body.signed_frame_sha256 -cne [string]$grantRecord.signed_frame_sha256) {
        Throw-Authority 'PRODUCTION_AUTHORITY_GRANT_RUNTIME_LINKAGE_INVALID'
    }
    return [pscustomobject]@{ paper_signed=$paperSigned[0]; proxy_grant=$proxyGrant[0];
        proxy_verified=$proxyVerified[0]; provider_commitment=$ProviderCommitment }
}

function Read-Journal([object]$Document, [object]$Capture, [object]$FrameFacts,
        [string]$ProviderCommitment, [object]$FreezeInfo) {
    $raw = $script:Utf8Strict.GetString($Document.bytes)
    if ($raw.Contains("`r") -or -not $raw.EndsWith("`n")) {
        Throw-Authority 'PRODUCTION_AUTHORITY_JOURNAL_ENCODING_INVALID'
    }
    $lines = @($raw.TrimEnd("`n") -split "`n")
    if ($lines.Count -ne 2 -or $lines[0] -cne 'MCACE_SERVER_AUTHORITY_ISSUANCE_JOURNAL_V3') {
        Throw-Authority 'PRODUCTION_AUTHORITY_JOURNAL_V3_REQUIRED'
    }
    $record = (ConvertFrom-StrictJson ($script:Utf8NoBom.GetBytes($lines[1])) 'issuance-journal-record').value
    $names = @('schema','capture_id','operation_attempt_id','attestation_id','observation_sequence',
        'authenticated_session_sha256','profile_sha256','provider_evidence_commitment_sha256',
        'input_frame_sha256','signed_frame_sha256','issued_at_epoch_ms','expires_at_epoch_ms')
    $observationFrame = $FrameFacts.by_type['SERVER_AUTHORITY_OBSERVATION'].record
    $observation = $FrameFacts.observation
    if (-not (Test-ExactProperties $record $names) -or
            [string]$record.schema -cne 'MCACE_SERVER_AUTHORITY_ISSUANCE_RECORD_V3' -or
            [string]$record.capture_id -cne [string]$Capture.capture_id -or
            [string]$record.operation_attempt_id -cne [string]$Capture.operation_attempt_id -or
            [string]$record.attestation_id -cne [string]$observation.attestation_id -or
            -not (Test-JsonInteger $record.observation_sequence) -or
            [long]$record.observation_sequence -ne [long]$observation.observation_sequence -or
            [string]$record.authenticated_session_sha256 -cne [string]$observationFrame.authenticated_session_sha256 -or
            [string]$record.profile_sha256 -cne [string]$FreezeInfo.profile_sha256 -or
            [string]$record.provider_evidence_commitment_sha256 -cne $ProviderCommitment -or
            [string]$record.input_frame_sha256 -cne [string]$observationFrame.input_frame_sha256 -or
            [string]$record.signed_frame_sha256 -cne [string]$observationFrame.signed_frame_sha256 -or
            -not (Test-JsonInteger $record.issued_at_epoch_ms) -or
            [long]$record.issued_at_epoch_ms -ne [long]$observation.issued_at_epoch_ms -or
            -not (Test-JsonInteger $record.expires_at_epoch_ms) -or
            [long]$record.expires_at_epoch_ms -ne [long]$observation.expires_at_epoch_ms) {
        Throw-Authority 'PRODUCTION_AUTHORITY_JOURNAL_OBSERVATION_MISMATCH'
    }
    return $record
}

function Assert-ProcessLedger([object]$Document, [object]$Capture, [object]$Artifacts,
        [bool]$Formal) {
    $ledger = (ConvertFrom-StrictJson $Document.bytes 'process-ledger').value
    $names = @('schema','source_commit','artifact_source_commit','capture_id','operation_attempt_id',
        'mode','processes','cleanup')
    $expectedMode = if ($Formal) { 'EXECUTED_REAL_PROCESSES' } else { 'FIXTURE_ONLY' }
    if (-not (Test-ExactProperties $ledger $names) -or
            [string]$ledger.schema -cne 'MCACE_PRODUCTION_AUTHORITY_PROCESS_LEDGER_V4' -or
            [string]$ledger.source_commit -cne [string]$Capture.source_commit -or
            [string]$ledger.artifact_source_commit -cne [string]$Capture.artifact_source_commit -or
            [string]$ledger.capture_id -cne [string]$Capture.capture_id -or
            [string]$ledger.operation_attempt_id -cne [string]$Capture.operation_attempt_id -or
            [string]$ledger.mode -cne $expectedMode -or @($ledger.processes).Count -lt 3) {
        Throw-Authority 'PRODUCTION_AUTHORITY_PROCESS_LEDGER_V4_INVALID'
    }
    $roles = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($process in @($ledger.processes)) {
        $processNames = @('role','platform','pid','started_at','stopped_at','exit_code',
            'executable_sha256','loaded_artifact_sha256','process_incarnation_id','real_process','fixture')
        if (-not (Test-ExactProperties $process $processNames) -or
                [string]$process.role -cnotin @('client','paper','proxy') -or
                -not $roles.Add([string]$process.role) -or
                -not (Test-JsonInteger $process.pid) -or [long]$process.pid -le 0 -or
                -not (Test-JsonInteger $process.exit_code) -or [long]$process.exit_code -ne 0 -or
                @($process.loaded_artifact_sha256).Count -lt 1) {
            Throw-Authority 'PRODUCTION_AUTHORITY_PROCESS_RECORD_INVALID'
        }
        Assert-Sha256 $process.executable_sha256 'PRODUCTION_AUTHORITY_PROCESS_EXECUTABLE_HASH_INVALID'
        foreach ($hash in @($process.loaded_artifact_sha256)) {
            Assert-Sha256 $hash 'PRODUCTION_AUTHORITY_PROCESS_LOADED_HASH_INVALID'
        }
        Assert-BoundedToken $process.process_incarnation_id 'PRODUCTION_AUTHORITY_PROCESS_INCARCERATION_ID_INVALID'
        $started = ConvertTo-UtcTime $process.started_at 'PRODUCTION_AUTHORITY_PROCESS_START_INVALID'
        $stopped = ConvertTo-UtcTime $process.stopped_at 'PRODUCTION_AUTHORITY_PROCESS_STOP_INVALID'
        if ($stopped -le $started) { Throw-Authority 'PRODUCTION_AUTHORITY_PROCESS_TIME_ORDER_INVALID' }
        Assert-JsonBoolean $process.real_process 'PRODUCTION_AUTHORITY_PROCESS_REAL_TYPE_INVALID'
        Assert-JsonBoolean $process.fixture 'PRODUCTION_AUTHORITY_PROCESS_FIXTURE_TYPE_INVALID'
        if ($Formal -and (-not [bool]$process.real_process -or [bool]$process.fixture)) {
            Throw-Authority 'PRODUCTION_AUTHORITY_NONREAL_PROCESS_REJECTED'
        }
    }
    if ((@($roles | Sort-Object) -join ',') -cne 'client,paper,proxy') {
        Throw-Authority 'PRODUCTION_AUTHORITY_PROCESS_ROLE_SET_INVALID'
    }
    $cleanupNames = @('mcace_owned_java_processes','server_processes','proxy_processes','open_ports',
        'temporary_files','automatic_actions')
    if (-not (Test-ExactProperties $ledger.cleanup $cleanupNames)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_CLEANUP_SCHEMA_INVALID'
    }
    foreach ($name in $cleanupNames) {
        if (-not (Test-JsonInteger $ledger.cleanup.$name) -or [long]$ledger.cleanup.$name -ne 0) {
            Throw-Authority "PRODUCTION_AUTHORITY_CLEANUP_NONZERO|$name"
        }
    }
    $paper = @($ledger.processes | Where-Object { [string]$_.role -ceq 'paper' })[0]
    $proxy = @($ledger.processes | Where-Object { [string]$_.role -ceq 'proxy' })[0]
    $expectedProxyRole = if ([string]$Capture.selected_proxy -ceq 'velocity') {
        'mcace_server_velocity'
    } else { 'mcace_server_bungeecord' }
    foreach ($required in @(
            [string]$Artifacts.artifacts.mcace_server_paper.entry.sha256,
            [string]$Artifacts.artifacts.grim.entry.sha256,
            [string]$Artifacts.artifacts.vulcan.entry.sha256)) {
        if ($required -cnotin @($paper.loaded_artifact_sha256)) {
            Throw-Authority 'PRODUCTION_AUTHORITY_PAPER_PROCESS_ARTIFACT_BINDING_INVALID'
        }
    }
    if ([string]$Artifacts.artifacts.$expectedProxyRole.entry.sha256 -cnotin
            @($proxy.loaded_artifact_sha256)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_PROXY_PROCESS_ARTIFACT_BINDING_INVALID'
    }
    return $ledger
}

function Assert-ArtifactsVsBundle([object]$Artifacts, [object]$Bundle) {
    $map = [ordered]@{
        mcace_server_paper='mcace-server-paper.jar'
        mcace_server_velocity='mcace-server-velocity.jar'
        mcace_server_bungeecord='mcace-server-bungeecord.jar'
    }
    foreach ($entry in $map.GetEnumerator()) {
        $artifact = $Artifacts.artifacts[[string]$entry.Key]
        # PowerShell variable names are case-insensitive: assigning to
        # `$bundle` would overwrite the `$Bundle` parameter after the first
        # iteration and silently discard the remaining release-bundle map.
        $bundleArtifact = $Bundle.artifacts[[string]$entry.Value]
        if ([string]$artifact.entry.release_bundle_file -cne [string]$entry.Value -or
                [string]$artifact.entry.sha256 -cne [string]$bundleArtifact.sha256 -or
                [long]$artifact.entry.size_bytes -ne [long]$bundleArtifact.size_bytes) {
            Throw-Authority "PRODUCTION_AUTHORITY_BUNDLE_ARTIFACT_CROSS_BINDING_INVALID|$($entry.Key)"
        }
    }
}

function Get-RawFrameSetSha256([object]$FrameFacts) {
    $stream = New-Object IO.MemoryStream
    try {
        Add-CanonicalText $stream 'mcace/production-authority/raw-frame-set/v1'
        Add-BigEndianInt32 $stream 2
        foreach ($name in @('BACKEND_AUTHORITY_GRANT','SERVER_AUTHORITY_OBSERVATION')) {
            $record = $FrameFacts.by_type[$name].record
            Add-CanonicalText $stream $name
            Add-CanonicalText $stream ([string]$record.input_frame_sha256)
            Add-CanonicalText $stream ([string]$record.signed_frame_sha256)
            Add-CanonicalText $stream ([string]$record.key_id_sha256)
        }
        return Get-BytesSha256 $stream.ToArray()
    } finally { $stream.Dispose() }
}

function Assert-SupervisorReceipt([object]$Document, [object]$DescriptorInfo, [object]$Tool,
        [string]$ScratchParent, [object]$RawSet, [string]$RawRoot, [object]$FreezeInfo,
        [object]$FrameFacts, [string]$FrameSetSha256, [string]$ProviderCommitment,
        [object]$Artifacts, [object]$Bundle, [bool]$Formal, [bool]$RequireCurrentlyValid,
        [byte[]]$ExpectedPayloadBytes = $null) {
    $receipt = $Document.value
    if (-not (Test-ExactProperties $receipt @('schema','signed_payload_base64',
            'signed_payload_sha256','signature_base64')) -or
            -not (Test-JsonString $receipt.schema) -or
            -not (Test-JsonString $receipt.signed_payload_base64) -or
            -not (Test-JsonString $receipt.signed_payload_sha256) -or
            -not (Test-JsonString $receipt.signature_base64) -or
            [string]$receipt.schema -cne 'MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_V1' -or
            [string]$receipt.signed_payload_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        Throw-Authority 'PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_V1_INVALID'
    }
    [byte[]]$payloadBytes = ConvertFrom-StrictBase64 $receipt.signed_payload_base64 256 65536 `
        'PRODUCTION_AUTHORITY_RECEIPT_PAYLOAD_BASE64_INVALID'
    [byte[]]$signature = ConvertFrom-StrictBase64 $receipt.signature_base64 64 64 `
        'PRODUCTION_AUTHORITY_RECEIPT_SIGNATURE_BASE64_INVALID'
    if ((Get-BytesSha256 $payloadBytes) -cne [string]$receipt.signed_payload_sha256) {
        Throw-Authority 'PRODUCTION_AUTHORITY_RECEIPT_PAYLOAD_HASH_MISMATCH'
    }
    if ($null -ne $ExpectedPayloadBytes -and
            -not (Test-BytesEqual $payloadBytes $ExpectedPayloadBytes)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_RECEIPT_REQUEST_PAYLOAD_MISMATCH'
    }
    Test-Ed25519Signature $Tool $DescriptorInfo.public_der $payloadBytes $signature `
        'supervisor-receipt' $ScratchParent
    $payload = (ConvertFrom-StrictJson $payloadBytes 'supervisor-receipt-payload').value
    $names = @('schema','artifact_class','source_commit','artifact_source_commit','product_version',
        'capture_id','operation_attempt_id','supervisor_instance_id','supervisor_run_id',
        'signer_key_id_sha256','challenge_nonce_base64','issued_at','expires_at',
        'raw_capture_manifest_sha256','raw_capture_manifest_size_bytes','raw_evidence_root_sha256',
        'raw_frame_set_sha256','raw_frame_count','provider_evidence_commitment_sha256',
        'event_chain_root_sha256','event_count','process_ledger_sha256','process_ledger_size_bytes',
        'paper_jar_sha256','paper_jar_size_bytes','velocity_jar_sha256','velocity_jar_size_bytes',
        'bungeecord_jar_sha256','bungeecord_jar_size_bytes','selected_proxy',
        'selected_proxy_jar_sha256','profile_sha256','topology_sha256','backend_key_id_sha256',
        'proxy_key_id_sha256','action_ceiling','automatic_action_count','cleanup_all_zero',
        'licensed_vulcan_sha256','genuine_provider_ids','test_fixture')
    $stringNames = @($names | Where-Object { $_ -notin @(
        'raw_capture_manifest_size_bytes','raw_frame_count','event_count',
        'process_ledger_size_bytes','paper_jar_size_bytes','velocity_jar_size_bytes',
        'bungeecord_jar_size_bytes','automatic_action_count','cleanup_all_zero',
        'genuine_provider_ids','test_fixture') })
    $integerNames = @('raw_capture_manifest_size_bytes','raw_frame_count','event_count',
        'process_ledger_size_bytes','paper_jar_size_bytes','velocity_jar_size_bytes',
        'bungeecord_jar_size_bytes','automatic_action_count')
    if (-not (Test-ExactProperties $payload $names)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_RECEIPT_BINDING_INVALID'
    }
    foreach ($name in $stringNames) {
        if (-not (Test-JsonString $payload.$name)) {
            Throw-Authority "PRODUCTION_AUTHORITY_RECEIPT_STRING_TYPE_INVALID|$name"
        }
    }
    foreach ($name in $integerNames) {
        if (-not (Test-JsonInteger $payload.$name)) {
            Throw-Authority "PRODUCTION_AUTHORITY_RECEIPT_INTEGER_TYPE_INVALID|$name"
        }
    }
    if ($payload.cleanup_all_zero -isnot [bool] -or $payload.test_fixture -isnot [bool]) {
        Throw-Authority 'PRODUCTION_AUTHORITY_RECEIPT_BOOLEAN_TYPE_INVALID'
    }
    if (-not (Test-JsonArray $payload.genuine_provider_ids)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_RECEIPT_PROVIDER_IDS_ARRAY_REQUIRED'
    }
    $providerIds = @($payload.genuine_provider_ids)
    if ($providerIds.Count -ne 2 -or
            @($providerIds | Where-Object { $_ -isnot [string] }).Count -ne 0 -or
            @($providerIds | Select-Object -Unique).Count -ne 2 -or
            (($providerIds | Sort-Object) -join ',') -cne 'grim,vulcan') {
        Throw-Authority 'PRODUCTION_AUTHORITY_RECEIPT_PROVIDER_IDS_INVALID'
    }
    $capture = $RawSet.capture
    if ([string]$payload.schema -cne 'MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_PAYLOAD_V1' -or
            [string]$payload.source_commit -cne [string]$capture.source_commit -or
            [string]$payload.artifact_source_commit -cne [string]$capture.artifact_source_commit -or
            [string]$payload.product_version -cne '0.0.1' -or
            [string]$payload.capture_id -cne [string]$capture.capture_id -or
            [string]$payload.operation_attempt_id -cne [string]$capture.operation_attempt_id -or
            [string]$payload.supervisor_instance_id -cne [string]$capture.supervisor.supervisor_instance_id -or
            [string]$payload.supervisor_run_id -cne [string]$capture.supervisor.supervisor_run_id -or
            [string]$payload.signer_key_id_sha256 -cne [string]$DescriptorInfo.key_id_sha256 -or
            [string]$payload.raw_capture_manifest_sha256 -cne [string]$RawSet.capture_document.sha256 -or
            -not (Test-JsonInteger $payload.raw_capture_manifest_size_bytes) -or
            [long]$payload.raw_capture_manifest_size_bytes -ne [long]$RawSet.capture_document.size_bytes -or
            [string]$payload.raw_evidence_root_sha256 -cne $RawRoot -or
            [string]$payload.raw_frame_set_sha256 -cne $FrameSetSha256 -or
            -not (Test-JsonInteger $payload.raw_frame_count) -or [long]$payload.raw_frame_count -ne 2 -or
            [string]$payload.provider_evidence_commitment_sha256 -cne $ProviderCommitment -or
            [string]$payload.event_chain_root_sha256 -cne [string]$capture.supervisor.event_chain_root_sha256 -or
            -not (Test-JsonInteger $payload.event_count) -or
            [long]$payload.event_count -ne [long]$capture.supervisor.event_count -or
            [string]$payload.process_ledger_sha256 -cne [string]$RawSet.documents.process_ledger.sha256 -or
            -not (Test-JsonInteger $payload.process_ledger_size_bytes) -or
            [long]$payload.process_ledger_size_bytes -ne [long]$RawSet.documents.process_ledger.size_bytes -or
            [string]$payload.paper_jar_sha256 -cne [string]$Bundle.artifacts['mcace-server-paper.jar'].sha256 -or
            -not (Test-JsonInteger $payload.paper_jar_size_bytes) -or
            [long]$payload.paper_jar_size_bytes -ne [long]$Bundle.artifacts['mcace-server-paper.jar'].size_bytes -or
            [string]$payload.velocity_jar_sha256 -cne [string]$Bundle.artifacts['mcace-server-velocity.jar'].sha256 -or
            -not (Test-JsonInteger $payload.velocity_jar_size_bytes) -or
            [long]$payload.velocity_jar_size_bytes -ne [long]$Bundle.artifacts['mcace-server-velocity.jar'].size_bytes -or
            [string]$payload.bungeecord_jar_sha256 -cne [string]$Bundle.artifacts['mcace-server-bungeecord.jar'].sha256 -or
            -not (Test-JsonInteger $payload.bungeecord_jar_size_bytes) -or
            [long]$payload.bungeecord_jar_size_bytes -ne [long]$Bundle.artifacts['mcace-server-bungeecord.jar'].size_bytes -or
            [string]$payload.selected_proxy -cne [string]$capture.selected_proxy -or
            [string]$payload.profile_sha256 -cne [string]$FreezeInfo.profile_sha256 -or
            [string]$payload.topology_sha256 -cne [string]$FreezeInfo.topology_sha256 -or
            [string]$payload.backend_key_id_sha256 -cne [string]$FreezeInfo.backend_key_id -or
            [string]$payload.proxy_key_id_sha256 -cne [string]$FreezeInfo.proxy_key_id -or
            [string]$payload.action_ceiling -cne 'MONITOR' -or
            -not (Test-JsonInteger $payload.automatic_action_count) -or
            [long]$payload.automatic_action_count -ne 0 -or
            $payload.cleanup_all_zero -isnot [bool] -or -not [bool]$payload.cleanup_all_zero -or
            [string]$payload.licensed_vulcan_sha256 -cne [string]$Artifacts.artifacts.vulcan.entry.sha256) {
        Throw-Authority 'PRODUCTION_AUTHORITY_RECEIPT_BINDING_INVALID'
    }
    $selectedFile = if ([string]$capture.selected_proxy -ceq 'velocity') {
        'mcace-server-velocity.jar'
    } else { 'mcace-server-bungeecord.jar' }
    if ([string]$payload.selected_proxy_jar_sha256 -cne [string]$Bundle.artifacts[$selectedFile].sha256) {
        Throw-Authority 'PRODUCTION_AUTHORITY_RECEIPT_SELECTED_PROXY_JAR_MISMATCH'
    }
    [byte[]]$challenge = ConvertFrom-StrictBase64 $payload.challenge_nonce_base64 32 32 `
        'PRODUCTION_AUTHORITY_RECEIPT_CHALLENGE_INVALID'
    $issued = ConvertTo-UtcTime $payload.issued_at 'PRODUCTION_AUTHORITY_RECEIPT_ISSUED_AT_INVALID'
    $expires = ConvertTo-UtcTime $payload.expires_at 'PRODUCTION_AUTHORITY_RECEIPT_EXPIRES_AT_INVALID'
    if ($issued -lt $RawSet.completed -or $expires -le $issued -or ($expires-$issued).TotalMinutes -gt 15 -or
            $issued -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_RECEIPT_TIME_WINDOW_INVALID'
    }
    Assert-JsonBoolean $payload.test_fixture 'PRODUCTION_AUTHORITY_RECEIPT_FIXTURE_TYPE_INVALID'
    if ($Formal) {
        if ([string]$payload.artifact_class -cne 'EXTERNAL_SUPERVISOR_SIGNED_PRODUCTION_CAPTURE' -or
                [bool]$payload.test_fixture -or ($RequireCurrentlyValid -and [DateTimeOffset]::UtcNow -ge $expires)) {
            Throw-Authority 'PRODUCTION_AUTHORITY_EXPIRED_OR_FIXTURE_RECEIPT_REJECTED'
        }
    } elseif ([string]$payload.artifact_class -cne 'TEST_SUPERVISOR_RECEIPT_FIXTURE') {
        Throw-Authority 'PRODUCTION_AUTHORITY_FIXTURE_RECEIPT_CLASS_INVALID'
    }
    return [pscustomobject]@{ value=$payload; payload_bytes=$payloadBytes;
        challenge_sha256=(Get-BytesSha256 $challenge); issued=$issued; expires=$expires }
}

function New-FileDescriptor([string]$Leaf, [object]$Document) {
    return [pscustomobject][ordered]@{
        relative_path=$Leaf; sha256=[string]$Document.sha256; size_bytes=[long]$Document.size_bytes
    }
}

function New-ReleaseBundleBinding([object]$Bundle) {
    return [pscustomobject][ordered]@{
        schema='MCACE_RELEASE_BUNDLE_V4'
        source_commit=[string]$Bundle.source_commit
        artifact_source_commit=[string]$Bundle.artifact_source_commit
        manifest=(New-FileDescriptor 'release-manifest.properties' $Bundle.manifest)
        sha256sums=(New-FileDescriptor 'SHA256SUMS' $Bundle.sums)
        paper_jar=(New-FileDescriptor 'mcace-server-paper.jar' $Bundle.artifacts['mcace-server-paper.jar'])
        velocity_jar=(New-FileDescriptor 'mcace-server-velocity.jar' $Bundle.artifacts['mcace-server-velocity.jar'])
        bungeecord_jar=(New-FileDescriptor 'mcace-server-bungeecord.jar' $Bundle.artifacts['mcace-server-bungeecord.jar'])
    }
}

function Invoke-AuthorityRawPrevalidation([object]$RawSet, [object]$DescriptorDocument,
        [string]$DescriptorPin, [object]$Tool,
        [string]$BundleRoot, [string]$ScratchParent, [bool]$Formal,
        [bool]$RequireFreshCapture) {
    $capture = $RawSet.capture
    $expectedSourceMode = if ($Formal) {
        'EXECUTED_EXTERNAL_SUPERVISOR_PRODUCTION_AUTHORITY'
    } else { 'FIXTURE_ONLY_SUPERVISED_NON_RELEASE_CAPTURE' }
    if ([string]$capture.source_mode -cne $expectedSourceMode -or
            ([bool]$capture.supervisor.fixture) -eq $Formal) {
        Throw-Authority 'PRODUCTION_AUTHORITY_CAPTURE_MODE_INVALID'
    }
    if ($Formal -and $RequireFreshCapture) {
        $elapsed = [DateTimeOffset]::UtcNow - $RawSet.completed
        if ($elapsed.TotalMinutes -lt -5 -or $elapsed.TotalHours -gt 24) {
            Throw-Authority 'PRODUCTION_AUTHORITY_CAPTURE_STALE_OR_FUTURE'
        }
    }
    $descriptorInfo = Assert-PublicDescriptor $DescriptorDocument $DescriptorPin $Formal
    $freezeInfo = Assert-FreezeManifest $RawSet.documents.freeze_manifest $capture `
        $descriptorInfo $DescriptorDocument.sha256 $Formal
    $artifacts = Read-ArtifactManifest $RawSet.documents.artifact_manifest $RawSet.root $capture $Formal
    $bundleResults = @(Read-ReleaseBundle $BundleRoot ([string]$capture.source_commit) `
        ([string]$capture.artifact_source_commit))
    if ($bundleResults.Count -ne 1 -or
            $bundleResults[0].PSObject.Properties.Name -cnotcontains 'artifacts') {
        $types = @($bundleResults | ForEach-Object {
            if ($null -eq $_) { '<null>' } else { $_.GetType().FullName }
        }) -join ','
        Throw-Authority "PRODUCTION_AUTHORITY_RELEASE_BUNDLE_RESULT_AMBIGUOUS|$types"
    }
    $bundle = $bundleResults[0]
    Assert-ArtifactsVsBundle $artifacts $bundle
    $providerRecords = Read-RawEventRecords $RawSet.documents.provider_events 'provider' $capture $Formal
    $paperRecords = Read-RawEventRecords $RawSet.documents.paper_events 'paper' $capture $Formal
    $proxyRecords = Read-RawEventRecords $RawSet.documents.proxy_events 'proxy' $capture $Formal
    $allRecords = @($providerRecords + $paperRecords + $proxyRecords)
    Assert-GlobalEventChain $allRecords $capture.supervisor
    $frames = Read-RawFrames $RawSet.documents.raw_frames $capture $freezeInfo $Tool `
        $ScratchParent $Formal
    $providerCommitment = Assert-ProviderEvidence $providerRecords $freezeInfo $frames
    $runtime = Assert-RuntimeEvents $paperRecords $proxyRecords $frames $providerCommitment $freezeInfo
    $journal = Read-Journal $RawSet.documents.issuance_journal $capture $frames `
        $providerCommitment $freezeInfo
    $process = Assert-ProcessLedger $RawSet.documents.process_ledger $capture $artifacts $Formal
    $processIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in @($process.processes)) { [void]$processIds.Add([string]$entry.process_incarnation_id) }
    foreach ($eventRecord in $allRecords) {
        if (-not $processIds.Contains([string]$eventRecord.body.process_incarnation_id)) {
            Throw-Authority 'PRODUCTION_AUTHORITY_EVENT_PROCESS_INCARCERATION_UNKNOWN'
        }
    }
    $rawRoot = Get-RawEvidenceRoot $RawSet.capture_document $RawSet.documents
    $frameSet = Get-RawFrameSetSha256 $frames
    return [pscustomobject]@{
        raw_set=$RawSet; descriptor_document=$DescriptorDocument; descriptor_info=$descriptorInfo
        freeze=$freezeInfo; artifacts=$artifacts
        bundle=$bundle; provider_records=$providerRecords; paper_records=$paperRecords
        proxy_records=$proxyRecords; frames=$frames; provider_commitment=$providerCommitment
        raw_root=$rawRoot; frame_set_sha256=$frameSet; journal=$journal; process=$process
    }
}

function Complete-AuthorityReceiptValidation([object]$Facts, [object]$ReceiptDocument,
        [object]$Tool, [string]$ScratchParent, [bool]$Formal,
        [bool]$RequireCurrentlyValidReceipt, [byte[]]$ExpectedPayloadBytes = $null) {
    $receipt = Assert-SupervisorReceipt $ReceiptDocument $Facts.descriptor_info $Tool $ScratchParent `
        $Facts.raw_set $Facts.raw_root $Facts.freeze $Facts.frames $Facts.frame_set_sha256 `
        $Facts.provider_commitment $Facts.artifacts $Facts.bundle $Formal `
        $RequireCurrentlyValidReceipt $ExpectedPayloadBytes
    $Facts | Add-Member NoteProperty receipt_document $ReceiptDocument -Force
    $Facts | Add-Member NoteProperty receipt $receipt -Force
    return $Facts
}

function Invoke-AuthorityRawValidation([object]$RawSet, [object]$DescriptorDocument,
        [object]$ReceiptDocument, [string]$DescriptorPin, [object]$Tool,
        [string]$BundleRoot, [string]$ScratchParent, [bool]$Formal,
        [bool]$RequireCurrentlyValidReceipt) {
    $facts = Invoke-AuthorityRawPrevalidation $RawSet $DescriptorDocument $DescriptorPin $Tool `
        $BundleRoot $ScratchParent $Formal $true
    return Complete-AuthorityReceiptValidation $facts $ReceiptDocument $Tool $ScratchParent `
        $Formal $RequireCurrentlyValidReceipt
}

function New-CryptoRandomBytes([int]$Count) {
    [byte[]]$bytes = New-Object byte[] $Count
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return $bytes
}

function New-AuthoritySupervisorReceiptPayload([object]$Facts, [byte[]]$Challenge,
        [DateTimeOffset]$IssuedAt, [DateTimeOffset]$ExpiresAt) {
    $capture = $Facts.raw_set.capture
    $bundle = $Facts.bundle
    $selectedFile = if ([string]$capture.selected_proxy -ceq 'velocity') {
        'mcace-server-velocity.jar'
    } else { 'mcace-server-bungeecord.jar' }
    return [pscustomobject][ordered]@{
        schema='MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_PAYLOAD_V1'
        artifact_class='EXTERNAL_SUPERVISOR_SIGNED_PRODUCTION_CAPTURE'
        source_commit=[string]$capture.source_commit
        artifact_source_commit=[string]$capture.artifact_source_commit
        product_version='0.0.1'
        capture_id=[string]$capture.capture_id
        operation_attempt_id=[string]$capture.operation_attempt_id
        supervisor_instance_id=[string]$capture.supervisor.supervisor_instance_id
        supervisor_run_id=[string]$capture.supervisor.supervisor_run_id
        signer_key_id_sha256=[string]$Facts.descriptor_info.key_id_sha256
        challenge_nonce_base64=[Convert]::ToBase64String($Challenge)
        issued_at=$IssuedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        expires_at=$ExpiresAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        raw_capture_manifest_sha256=[string]$Facts.raw_set.capture_document.sha256
        raw_capture_manifest_size_bytes=[long]$Facts.raw_set.capture_document.size_bytes
        raw_evidence_root_sha256=[string]$Facts.raw_root
        raw_frame_set_sha256=[string]$Facts.frame_set_sha256
        raw_frame_count=2
        provider_evidence_commitment_sha256=[string]$Facts.provider_commitment
        event_chain_root_sha256=[string]$capture.supervisor.event_chain_root_sha256
        event_count=[long]$capture.supervisor.event_count
        process_ledger_sha256=[string]$Facts.raw_set.documents.process_ledger.sha256
        process_ledger_size_bytes=[long]$Facts.raw_set.documents.process_ledger.size_bytes
        paper_jar_sha256=[string]$bundle.artifacts['mcace-server-paper.jar'].sha256
        paper_jar_size_bytes=[long]$bundle.artifacts['mcace-server-paper.jar'].size_bytes
        velocity_jar_sha256=[string]$bundle.artifacts['mcace-server-velocity.jar'].sha256
        velocity_jar_size_bytes=[long]$bundle.artifacts['mcace-server-velocity.jar'].size_bytes
        bungeecord_jar_sha256=[string]$bundle.artifacts['mcace-server-bungeecord.jar'].sha256
        bungeecord_jar_size_bytes=[long]$bundle.artifacts['mcace-server-bungeecord.jar'].size_bytes
        selected_proxy=[string]$capture.selected_proxy
        selected_proxy_jar_sha256=[string]$bundle.artifacts[$selectedFile].sha256
        profile_sha256=[string]$Facts.freeze.profile_sha256
        topology_sha256=[string]$Facts.freeze.topology_sha256
        backend_key_id_sha256=[string]$Facts.freeze.backend_key_id
        proxy_key_id_sha256=[string]$Facts.freeze.proxy_key_id
        action_ceiling='MONITOR'
        automatic_action_count=0
        cleanup_all_zero=$true
        licensed_vulcan_sha256=[string]$Facts.artifacts.artifacts.vulcan.entry.sha256
        genuine_provider_ids=@('grim','vulcan')
        test_fixture=$false
    }
}

function ConvertTo-CanonicalJsonBytes([object]$Value) {
    $json = (($Value | ConvertTo-Json -Depth 20 -Compress) -replace "`r`n","`n")
    return $script:Utf8NoBom.GetBytes($json)
}

function Assert-ExternalExchangePaths([string]$RequestPath, [string]$ReceiptPath,
        [string]$DescriptorPath, [string]$ReleaseRoot, [string]$OutputRoot) {
    foreach ($path in @($RequestPath,$ReceiptPath)) {
        if ([string]::IsNullOrWhiteSpace($path) -or -not [IO.Path]::IsPathRooted($path)) {
            Throw-Authority 'PRODUCTION_AUTHORITY_EXCHANGE_ABSOLUTE_PATH_REQUIRED'
        }
    }
    $request = [IO.Path]::GetFullPath($RequestPath)
    $receipt = [IO.Path]::GetFullPath($ReceiptPath)
    $descriptor = [IO.Path]::GetFullPath($DescriptorPath)
    $leaves = @([IO.Path]::GetFileName($request),[IO.Path]::GetFileName($receipt),
        [IO.Path]::GetFileName($descriptor))
    if ($request -ceq $receipt -or @($leaves | Sort-Object -Unique).Count -ne 3) {
        Throw-Authority 'PRODUCTION_AUTHORITY_EXCHANGE_DISTINCT_LEAVES_REQUIRED'
    }
    foreach ($path in @($request,$receipt)) {
        $parent = [IO.Path]::GetDirectoryName($path)
        if ([string]::IsNullOrWhiteSpace($parent) -or -not [IO.Directory]::Exists($parent)) {
            Throw-Authority 'PRODUCTION_AUTHORITY_EXCHANGE_PARENT_REQUIRED'
        }
        Assert-PathChainNoReparse $parent $true
        Assert-PathChainNoReparse $path $false
        if ([IO.File]::Exists($path) -or [IO.Directory]::Exists($path)) {
            Throw-Authority 'PRODUCTION_AUTHORITY_EXCHANGE_PATH_MUST_BE_INITIALLY_ABSENT'
        }
    }
    $excluded = @($script:RepoRoot,[IO.Path]::GetFullPath($ReleaseRoot),[IO.Path]::GetFullPath($OutputRoot))
    foreach ($path in @($descriptor,$request,$receipt)) {
        foreach ($root in $excluded) {
            $prefix = $root.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
            if ($path.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or $path -ieq $root) {
                Throw-Authority 'PRODUCTION_AUTHORITY_EXCHANGE_PATH_INSIDE_PROTECTED_ROOT'
            }
        }
    }
    return [pscustomobject]@{ request=$request; receipt=$receipt }
}

function Write-AtomicSigningRequest([string]$Path, [object]$RequestValue) {
    [byte[]]$bytes = $script:Utf8NoBom.GetBytes(
        ((($RequestValue | ConvertTo-Json -Depth 20) -replace "`r`n","`n") + "`n"))
    $parent = [IO.Path]::GetDirectoryName($Path)
    $temporary = Join-Path $parent ('.mcace-authority-signing-request-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllBytes($temporary,$bytes)
        Assert-PathChainNoReparse $temporary $true
        if ([IO.File]::Exists($Path) -or [IO.Directory]::Exists($Path)) {
            Throw-Authority 'PRODUCTION_AUTHORITY_SIGNING_REQUEST_TARGET_APPEARED'
        }
        [IO.File]::Move($temporary,$Path)
        $document = Read-JsonDocument $Path 'supervisor-signing-request'
        if (-not (Test-BytesEqual $document.bytes $bytes)) {
            Throw-Authority 'PRODUCTION_AUTHORITY_SIGNING_REQUEST_ATOMIC_WRITE_MISMATCH'
        }
        return $document
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function New-AuthoritySigningRequest([object]$Facts, [string]$RequestPath,
        [string]$ReceiptPath, [string]$DescriptorPin, [int]$ValiditySeconds) {
    [byte[]]$challenge = New-CryptoRandomBytes 32
    $issued = [DateTimeOffset]::UtcNow
    $notAfter = $issued.AddSeconds($ValiditySeconds)
    $payload = New-AuthoritySupervisorReceiptPayload $Facts $challenge $issued $notAfter
    [byte[]]$payloadBytes = ConvertTo-CanonicalJsonBytes $payload
    $bundle = $Facts.bundle
    $capture = $Facts.raw_set.capture
    $requestValue = [pscustomobject][ordered]@{
        schema='MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_SIGNING_REQUEST_V1'
        artifact_class='EXTERNAL_PRODUCTION_AUTHORITY_RECEIPT_SIGNING_REQUEST'
        request_id=[guid]::NewGuid().ToString('D')
        issued_at=$issued.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        not_after=$notAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        output_receipt_path=$ReceiptPath
        capture_supervisor_descriptor_sha256=$DescriptorPin.ToLowerInvariant()
        signer_key_id_sha256=[string]$Facts.descriptor_info.key_id_sha256
        source_commit=[string]$capture.source_commit
        artifact_source_commit=[string]$capture.artifact_source_commit
        product_version='0.0.1'
        capture_id=[string]$capture.capture_id
        operation_attempt_id=[string]$capture.operation_attempt_id
        challenge_nonce_base64=[Convert]::ToBase64String($challenge)
        challenge_sha256=(Get-BytesSha256 $challenge)
        signed_payload_base64=[Convert]::ToBase64String($payloadBytes)
        signed_payload_sha256=(Get-BytesSha256 $payloadBytes)
        signed_payload_size_bytes=[long]$payloadBytes.Length
        release_bundle_source_commit=[string]$bundle.source_commit
        release_bundle_artifact_source_commit=[string]$bundle.artifact_source_commit
        paper_jar_sha256=[string]$bundle.artifacts['mcace-server-paper.jar'].sha256
        paper_jar_size_bytes=[long]$bundle.artifacts['mcace-server-paper.jar'].size_bytes
        velocity_jar_sha256=[string]$bundle.artifacts['mcace-server-velocity.jar'].sha256
        velocity_jar_size_bytes=[long]$bundle.artifacts['mcace-server-velocity.jar'].size_bytes
        bungeecord_jar_sha256=[string]$bundle.artifacts['mcace-server-bungeecord.jar'].sha256
        bungeecord_jar_size_bytes=[long]$bundle.artifacts['mcace-server-bungeecord.jar'].size_bytes
        raw_capture_manifest_sha256=[string]$Facts.raw_set.capture_document.sha256
        raw_capture_manifest_size_bytes=[long]$Facts.raw_set.capture_document.size_bytes
        raw_evidence_root_sha256=[string]$Facts.raw_root
        raw_frame_set_sha256=[string]$Facts.frame_set_sha256
        provider_evidence_commitment_sha256=[string]$Facts.provider_commitment
        profile_sha256=[string]$Facts.freeze.profile_sha256
        topology_sha256=[string]$Facts.freeze.topology_sha256
        process_ledger_sha256=[string]$Facts.raw_set.documents.process_ledger.sha256
        process_ledger_size_bytes=[long]$Facts.raw_set.documents.process_ledger.size_bytes
        issuance_journal_sha256=[string]$Facts.raw_set.documents.issuance_journal.sha256
        issuance_journal_size_bytes=[long]$Facts.raw_set.documents.issuance_journal.size_bytes
        test_fixture=$false
    }
    $document = Write-AtomicSigningRequest $RequestPath $requestValue
    return [pscustomobject]@{ document=$document; value=$requestValue; payload_bytes=$payloadBytes;
        challenge_sha256=(Get-BytesSha256 $challenge); expires=$notAfter }
}

function Assert-AuthoritySigningRequestStable([object]$SigningRequest) {
    $requestReread = Read-JsonDocument $SigningRequest.document.absolute 'supervisor-signing-request-reread'
    if ($requestReread.identity -cne $SigningRequest.document.identity -or
            $requestReread.sha256 -cne $SigningRequest.document.sha256 -or
            -not (Test-BytesEqual $requestReread.bytes $SigningRequest.document.bytes)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_SIGNING_REQUEST_MUTATED_DURING_HANDOFF'
    }
}

function Test-AuthoritySharingViolation([Exception]$Exception) {
    $cursor = $Exception
    while ($null -ne $cursor) {
        if ($cursor.HResult -eq -2147024864) { return $true } # HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION)
        $cursor = $cursor.InnerException
    }
    return $false
}

function Wait-AuthoritySupervisorReceipt([string]$ReceiptPath, [int]$WaitSeconds,
        [object]$SigningRequest) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($WaitSeconds)
    while ($true) {
        if ([DateTimeOffset]::UtcNow -ge $deadline) {
            Throw-Authority 'PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_WAIT_TIMEOUT'
        }
        if ([IO.File]::Exists($ReceiptPath)) {
            try {
                $receipt = Read-JsonDocument $ReceiptPath 'supervisor-receipt'
                Assert-AuthoritySigningRequestStable $SigningRequest
                return $receipt
            } catch {
                if (-not (Test-AuthoritySharingViolation $_.Exception)) { throw }
            }
        }
        Start-Sleep -Milliseconds 250
    }
}

function New-AuthorityReport([object]$Facts, [string]$GeneratedAt, [bool]$Formal) {
    $capture = $Facts.raw_set.capture
    $bundle = $Facts.bundle
    return [pscustomobject][ordered]@{
        schema='MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_REPORT_V4'
        generated_at=$GeneratedAt
        source_mode=[string]$capture.source_mode
        source_commit=[string]$capture.source_commit
        artifact_source_commit=[string]$capture.artifact_source_commit
        product_version='0.0.1'
        evidence_class=if ($Formal) {
            'EXTERNAL_SUPERVISOR_SIGNED_PRODUCTION_AUTHORITY_PREPUBLICATION'
        } else { 'TEST_FIXTURE_DIAGNOSTIC_ONLY' }
        capture_id=[string]$capture.capture_id
        operation_attempt_id=[string]$capture.operation_attempt_id
        selected_proxy=[string]$capture.selected_proxy
        profile_sha256=[string]$Facts.freeze.profile_sha256
        provider_evidence_commitment_sha256=[string]$Facts.provider_commitment
        topology_sha256=[string]$Facts.freeze.topology_sha256
        supervisor_descriptor_sha256=[string]$Facts.descriptor_document.sha256
        supervisor_key_id_sha256=[string]$Facts.descriptor_info.key_id_sha256
        supervisor_receipt_sha256=[string]$Facts.receipt_document.sha256
        raw_evidence_root_sha256=[string]$Facts.raw_root
        raw_frame_set_sha256=[string]$Facts.frame_set_sha256
        raw_frame_count=2
        event_chain_root_sha256=[string]$capture.supervisor.event_chain_root_sha256
        event_count=[long]$capture.supervisor.event_count
        paper_jar_sha256=[string]$bundle.artifacts['mcace-server-paper.jar'].sha256
        velocity_jar_sha256=[string]$bundle.artifacts['mcace-server-velocity.jar'].sha256
        bungeecord_jar_sha256=[string]$bundle.artifacts['mcace-server-bungeecord.jar'].sha256
        licensed_vulcan_sha256=[string]$Facts.artifacts.artifacts.vulcan.entry.sha256
        genuine_provider_ids=@('grim','vulcan')
        server_confirmed_only=$true
        action_ceiling='MONITOR'
        automatic_action_count=0
        cleanup_all_zero=$true
        independent_supervisor_signature_verified=$true
        fixture=[bool](-not $Formal)
        release_eligible=$false
        passed=$true
        limitations=@('PREPUBLICATION_OUTPUT_REQUIRES_PUBLISHER_AND_READINESS_RAW_REVALIDATION')
    }
}

function Write-JsonFile([string]$Path, [object]$Value) {
    $json = (($Value | ConvertTo-Json -Depth 20) -replace "`r`n","`n") + "`n"
    [byte[]]$bytes = $script:Utf8NoBom.GetBytes($json)
    [IO.File]::WriteAllBytes($Path,$bytes)
    return [pscustomobject]@{ absolute=$Path; bytes=$bytes; sha256=(Get-BytesSha256 $bytes);
        size_bytes=[long]$bytes.Length; value=$Value }
}

function New-RawEvidenceBinding([object]$Facts) {
    $raw = [ordered]@{
        capture_manifest=(New-FileDescriptor 'raw-capture-manifest.json' $Facts.raw_set.capture_document)
    }
    foreach ($entry in $script:RawRoles.GetEnumerator()) {
        $raw[[string]$entry.Key] = New-FileDescriptor ([string]$entry.Value) `
            $Facts.raw_set.documents[[string]$entry.Key]
    }
    $raw.capture_supervisor_public_descriptor = New-FileDescriptor `
        'capture-supervisor-public-descriptor.json' $Facts.descriptor_document
    $raw.supervisor_receipt = New-FileDescriptor 'supervisor-receipt.json' $Facts.receipt_document
    return [pscustomobject]$raw
}

function Write-AuthorityPackage([object]$Facts, [string]$Destination, [bool]$Formal) {
    if ([string]::IsNullOrWhiteSpace($Destination) -or -not [IO.Path]::IsPathRooted($Destination)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_OUTPUT_DIRECTORY_ABSOLUTE_REQUIRED'
    }
    $final = [IO.Path]::GetFullPath($Destination)
    if ([IO.File]::Exists($final) -or [IO.Directory]::Exists($final)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_OUTPUT_ALREADY_EXISTS'
    }
    $parent = [IO.Path]::GetDirectoryName($final)
    if ([string]::IsNullOrWhiteSpace($parent) -or -not [IO.Directory]::Exists($parent)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_OUTPUT_PARENT_REQUIRED'
    }
    Assert-PathChainNoReparse $parent $true
    $stage = Join-Path $parent ('.mcace-authority-v4-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    $committed = $false
    try {
        $copyMap = [ordered]@{
            'raw-capture-manifest.json'=$Facts.raw_set.capture_document
            'freeze-manifest.json'=$Facts.raw_set.documents.freeze_manifest
            'artifact-manifest.json'=$Facts.raw_set.documents.artifact_manifest
            'provider-events.jsonl'=$Facts.raw_set.documents.provider_events
            'paper-events.jsonl'=$Facts.raw_set.documents.paper_events
            'proxy-events.jsonl'=$Facts.raw_set.documents.proxy_events
            'issuance-journal.log'=$Facts.raw_set.documents.issuance_journal
            'process-ledger.json'=$Facts.raw_set.documents.process_ledger
            'raw-frames.jsonl'=$Facts.raw_set.documents.raw_frames
            'capture-supervisor-public-descriptor.json'=$Facts.descriptor_document
            'supervisor-receipt.json'=$Facts.receipt_document
        }
        foreach ($entry in $copyMap.GetEnumerator()) {
            [IO.File]::WriteAllBytes((Join-Path $stage ([string]$entry.Key)),[byte[]]$entry.Value.bytes)
        }
        # The raw artifact manifest is only independently revalidatable when
        # the exact bytes it names travel with the package.  Keep them in the
        # manifest's fixed `artifacts/` namespace; the supervisor receipt and
        # process ledger bind their hashes, while the release bundle separately
        # binds the three publishable server JARs.
        $artifactStage = Join-Path $stage $script:PackagedArtifactDirectoryName
        [IO.Directory]::CreateDirectory($artifactStage) | Out-Null
        foreach ($artifactRole in @($Facts.artifacts.artifacts.Keys | Sort-Object)) {
            $artifact = $Facts.artifacts.artifacts[$artifactRole]
            $relative = [string]$artifact.entry.relative_path
            if ($relative -cnotmatch '^artifacts/(?<leaf>[A-Za-z0-9._-]+\.(?:jar|bin))$') {
                Throw-Authority "PRODUCTION_AUTHORITY_PACKAGED_ARTIFACT_PATH_INVALID|$artifactRole"
            }
            [IO.File]::WriteAllBytes((Join-Path $artifactStage $Matches.leaf),
                [byte[]]$artifact.document.bytes)
        }
        $generated = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        if ([DateTimeOffset]::Parse($generated) -ge $Facts.receipt.expires) {
            Throw-Authority 'PRODUCTION_AUTHORITY_RECEIPT_EXPIRED_BEFORE_PACKAGE_COMMIT'
        }
        $reportValue = New-AuthorityReport $Facts $generated $Formal
        $reportDoc = Write-JsonFile (Join-Path $stage 'report.json') $reportValue
        $bindingValue = [pscustomobject][ordered]@{
            schema='MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_BINDING_V4'
            report_schema='MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_REPORT_V4'
            generated_at=$generated
            report_sha256=$reportDoc.sha256
            report_size_bytes=$reportDoc.size_bytes
            source_commit=[string]$Facts.raw_set.capture.source_commit
            artifact_source_commit=[string]$Facts.raw_set.capture.artifact_source_commit
            capture_id=[string]$Facts.raw_set.capture.capture_id
            operation_attempt_id=[string]$Facts.raw_set.capture.operation_attempt_id
            supervisor_descriptor_sha256=[string]$Facts.descriptor_document.sha256
            supervisor_receipt_sha256=[string]$Facts.receipt_document.sha256
            raw_evidence_root_sha256=[string]$Facts.raw_root
            raw_evidence=(New-RawEvidenceBinding $Facts)
            release_bundle=(New-ReleaseBundleBinding $Facts.bundle)
            release_eligible=$false
            passed=$true
        }
        $bindingDoc = Write-JsonFile (Join-Path $stage 'binding.json') $bindingValue
        $commitValue = [pscustomobject][ordered]@{
            schema='MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_COMMIT_V4'
            report_schema='MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_REPORT_V4'
            binding_schema='MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_BINDING_V4'
            generated_at=$generated
            report_sha256=$reportDoc.sha256
            report_size_bytes=$reportDoc.size_bytes
            binding_sha256=$bindingDoc.sha256
            binding_size_bytes=$bindingDoc.size_bytes
            supervisor_receipt_sha256=[string]$Facts.receipt_document.sha256
            raw_evidence_root_sha256=[string]$Facts.raw_root
            source_commit=[string]$Facts.raw_set.capture.source_commit
            artifact_source_commit=[string]$Facts.raw_set.capture.artifact_source_commit
            capture_id=[string]$Facts.raw_set.capture.capture_id
            operation_attempt_id=[string]$Facts.raw_set.capture.operation_attempt_id
            release_eligible=$false
            committed=$true
        }
        $null = Write-JsonFile (Join-Path $stage 'commit.json') $commitValue
        $actual = @(Get-ChildItem -LiteralPath $stage -Force)
        $expectedRootNames = @($script:PackageNames + $script:PackagedArtifactDirectoryName)
        if ($actual.Count -ne $expectedRootNames.Count -or
                ((@($actual.Name | Sort-Object) -join '|') -cne (($expectedRootNames | Sort-Object) -join '|'))) {
            Throw-Authority 'PRODUCTION_AUTHORITY_STAGED_PACKAGE_FILE_SET_INVALID'
        }
        $artifactActual = @(Get-ChildItem -LiteralPath $artifactStage -Force)
        if ($artifactActual.Count -ne $script:PackagedArtifactCount -or
                @($artifactActual | Where-Object {
                    $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
                }).Count -ne 0) {
            Throw-Authority 'PRODUCTION_AUTHORITY_STAGED_ARTIFACT_SET_INVALID'
        }
        [IO.Directory]::Move($stage,$final)
        $committed = $true
        return $final
    } finally {
        if (-not $committed -and [IO.Directory]::Exists($stage)) {
            Assert-PathChainNoReparse $stage $true
            [IO.Directory]::Delete($stage,$true)
        }
    }
}

function Assert-AuthorityOutputDocuments([string]$PackageRoot, [object]$Facts) {
    $reportDoc = Read-JsonDocument (Join-Path $PackageRoot 'report.json') 'authority-report'
    $bindingDoc = Read-JsonDocument (Join-Path $PackageRoot 'binding.json') 'authority-binding'
    $commitDoc = Read-JsonDocument (Join-Path $PackageRoot 'commit.json') 'authority-commit'
    $report = $reportDoc.value; $binding = $bindingDoc.value; $commit = $commitDoc.value
    $reportNames = @('schema','generated_at','source_mode','source_commit','artifact_source_commit',
        'product_version','evidence_class','capture_id','operation_attempt_id','selected_proxy',
        'profile_sha256','provider_evidence_commitment_sha256','topology_sha256',
        'supervisor_descriptor_sha256','supervisor_key_id_sha256','supervisor_receipt_sha256',
        'raw_evidence_root_sha256','raw_frame_set_sha256','raw_frame_count','event_chain_root_sha256',
        'event_count','paper_jar_sha256','velocity_jar_sha256','bungeecord_jar_sha256',
        'licensed_vulcan_sha256','genuine_provider_ids','server_confirmed_only','action_ceiling',
        'automatic_action_count','cleanup_all_zero','independent_supervisor_signature_verified',
        'fixture','release_eligible','passed','limitations')
    if (-not (Test-ExactProperties $report $reportNames) -or
            [string]$report.schema -cne 'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_REPORT_V4' -or
            [string]$report.source_commit -cne [string]$Facts.raw_set.capture.source_commit -or
            [string]$report.artifact_source_commit -cne [string]$Facts.raw_set.capture.artifact_source_commit -or
            [string]$report.capture_id -cne [string]$Facts.raw_set.capture.capture_id -or
            [string]$report.operation_attempt_id -cne [string]$Facts.raw_set.capture.operation_attempt_id -or
            [string]$report.profile_sha256 -cne [string]$Facts.freeze.profile_sha256 -or
            [string]$report.provider_evidence_commitment_sha256 -cne [string]$Facts.provider_commitment -or
            [string]$report.raw_evidence_root_sha256 -cne [string]$Facts.raw_root -or
            [string]$report.raw_frame_set_sha256 -cne [string]$Facts.frame_set_sha256 -or
            $report.server_confirmed_only -isnot [bool] -or -not [bool]$report.server_confirmed_only -or
            $report.independent_supervisor_signature_verified -isnot [bool] -or
                -not [bool]$report.independent_supervisor_signature_verified -or
            $report.release_eligible -isnot [bool] -or [bool]$report.release_eligible -or
            $report.passed -isnot [bool] -or -not [bool]$report.passed -or
            [string]$report.action_ceiling -cne 'MONITOR' -or [long]$report.automatic_action_count -ne 0 -or
            ((@($report.genuine_provider_ids) | Sort-Object) -join ',') -cne 'grim,vulcan') {
        Throw-Authority 'PRODUCTION_AUTHORITY_REPORT_V4_INVALID'
    }
    $generated = ConvertTo-UtcTime $report.generated_at 'PRODUCTION_AUTHORITY_REPORT_TIME_INVALID'
    if ($generated -lt $Facts.receipt.issued -or $generated -ge $Facts.receipt.expires) {
        Throw-Authority 'PRODUCTION_AUTHORITY_REPORT_OUTSIDE_RECEIPT_WINDOW'
    }
    $bindingNames = @('schema','report_schema','generated_at','report_sha256','report_size_bytes',
        'source_commit','artifact_source_commit','capture_id','operation_attempt_id',
        'supervisor_descriptor_sha256','supervisor_receipt_sha256','raw_evidence_root_sha256',
        'raw_evidence','release_bundle','release_eligible','passed')
    if (-not (Test-ExactProperties $binding $bindingNames) -or
            [string]$binding.schema -cne 'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_BINDING_V4' -or
            [string]$binding.report_schema -cne [string]$report.schema -or
            [string]$binding.generated_at -cne [string]$report.generated_at -or
            [string]$binding.report_sha256 -cne [string]$reportDoc.sha256 -or
            [long]$binding.report_size_bytes -ne [long]$reportDoc.size_bytes -or
            [string]$binding.raw_evidence_root_sha256 -cne [string]$Facts.raw_root -or
            $binding.release_eligible -isnot [bool] -or [bool]$binding.release_eligible -or
            $binding.passed -isnot [bool] -or -not [bool]$binding.passed) {
        Throw-Authority 'PRODUCTION_AUTHORITY_BINDING_V4_INVALID'
    }
    $rawExpected = New-RawEvidenceBinding $Facts
    if (-not (Test-ExactProperties $binding.raw_evidence @($rawExpected.PSObject.Properties.Name))) {
        Throw-Authority 'PRODUCTION_AUTHORITY_RAW_EVIDENCE_BINDING_SET_INVALID'
    }
    foreach ($property in @($rawExpected.PSObject.Properties)) {
        $actual = $binding.raw_evidence.($property.Name)
        $wanted = $property.Value
        if (-not (Test-ExactProperties $actual @('relative_path','sha256','size_bytes')) -or
                [string]$actual.relative_path -cne [string]$wanted.relative_path -or
                [string]$actual.sha256 -cne [string]$wanted.sha256 -or
                [long]$actual.size_bytes -ne [long]$wanted.size_bytes) {
            Throw-Authority "PRODUCTION_AUTHORITY_RAW_EVIDENCE_BINDING_MISMATCH|$($property.Name)"
        }
    }
    $expectedBundle = New-ReleaseBundleBinding $Facts.bundle
    if (($binding.release_bundle | ConvertTo-Json -Depth 8 -Compress) -cne
            ($expectedBundle | ConvertTo-Json -Depth 8 -Compress)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_RELEASE_BUNDLE_BINDING_MISMATCH'
    }
    $commitNames = @('schema','report_schema','binding_schema','generated_at','report_sha256',
        'report_size_bytes','binding_sha256','binding_size_bytes','supervisor_receipt_sha256',
        'raw_evidence_root_sha256','source_commit','artifact_source_commit','capture_id',
        'operation_attempt_id','release_eligible','committed')
    if (-not (Test-ExactProperties $commit $commitNames) -or
            [string]$commit.schema -cne 'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_COMMIT_V4' -or
            [string]$commit.report_schema -cne [string]$report.schema -or
            [string]$commit.binding_schema -cne [string]$binding.schema -or
            [string]$commit.generated_at -cne [string]$report.generated_at -or
            [string]$commit.report_sha256 -cne [string]$reportDoc.sha256 -or
            [long]$commit.report_size_bytes -ne [long]$reportDoc.size_bytes -or
            [string]$commit.binding_sha256 -cne [string]$bindingDoc.sha256 -or
            [long]$commit.binding_size_bytes -ne [long]$bindingDoc.size_bytes -or
            [string]$commit.supervisor_receipt_sha256 -cne [string]$Facts.receipt_document.sha256 -or
            [string]$commit.raw_evidence_root_sha256 -cne [string]$Facts.raw_root -or
            $commit.release_eligible -isnot [bool] -or [bool]$commit.release_eligible -or
            $commit.committed -isnot [bool] -or -not [bool]$commit.committed) {
        Throw-Authority 'PRODUCTION_AUTHORITY_COMMIT_V4_INVALID'
    }
    return [pscustomobject]@{ report=$reportDoc; binding=$bindingDoc; commit=$commitDoc }
}

function Assert-ExactPackageDirectory([string]$Root) {
    $absolute = [IO.Path]::GetFullPath($Root)
    Assert-PathChainNoReparse $absolute $true
    if (-not (Test-Path -LiteralPath $absolute -PathType Container)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_PACKAGE_DIRECTORY_REQUIRED'
    }
    $entries = @(Get-ChildItem -LiteralPath $absolute -Force -ErrorAction Stop)
    $expectedRootNames = @($script:PackageNames + $script:PackagedArtifactDirectoryName)
    if ($entries.Count -ne $expectedRootNames.Count -or
            ((@($entries.Name | Sort-Object) -join '|') -cne (($expectedRootNames | Sort-Object) -join '|'))) {
        Throw-Authority 'PRODUCTION_AUTHORITY_PACKAGE_EXACT_V4_SET_REQUIRED'
    }
    foreach ($entry in $entries) {
        $isArtifactDirectory = $entry.Name -ceq $script:PackagedArtifactDirectoryName
        if (($entry.PSIsContainer -ne $isArtifactDirectory) -or
                ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($entry.Attributes -band [IO.FileAttributes]::Hidden) -ne 0) {
            Throw-Authority 'PRODUCTION_AUTHORITY_PACKAGE_REGULAR_NO_REPARSE_SET_REQUIRED'
        }
    }
    $artifactDirectory = Join-Path $absolute $script:PackagedArtifactDirectoryName
    Assert-PathChainNoReparse $artifactDirectory $true
    $artifactEntries = @(Get-ChildItem -LiteralPath $artifactDirectory -Force -ErrorAction Stop)
    if ($artifactEntries.Count -ne $script:PackagedArtifactCount) {
        Throw-Authority 'PRODUCTION_AUTHORITY_PACKAGE_ARTIFACT_COUNT_INVALID'
    }
    foreach ($artifactEntry in $artifactEntries) {
        if ($artifactEntry.PSIsContainer -or
                ($artifactEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($artifactEntry.Attributes -band [IO.FileAttributes]::Hidden) -ne 0 -or
                [string]$artifactEntry.Name -cnotmatch '^[A-Za-z0-9._-]+\.(?:jar|bin)$') {
            Throw-Authority 'PRODUCTION_AUTHORITY_PACKAGE_ARTIFACT_REGULAR_NO_REPARSE_REQUIRED'
        }
    }
    return $absolute
}

function Invoke-ValidatePublishedPackage([string]$Root, [string]$DescriptorPin,
        [object]$Tool, [string]$BundleRoot, [bool]$RequireCurrentReceipt) {
    $package = Assert-ExactPackageDirectory $Root
    $raw = Read-RawCaptureSet (Join-Path $package 'raw-capture-manifest.json')
    $descriptor = Read-JsonDocument (Join-Path $package 'capture-supervisor-public-descriptor.json') `
        'capture-supervisor-public-descriptor'
    $receipt = Read-JsonDocument (Join-Path $package 'supervisor-receipt.json') 'supervisor-receipt'
    $facts = Invoke-AuthorityRawValidation $raw $descriptor $receipt $DescriptorPin $Tool `
        $BundleRoot ([IO.Path]::GetDirectoryName($package)) $true $RequireCurrentReceipt
    $outputs = Assert-AuthorityOutputDocuments $package $facts
    return [pscustomobject]@{ package=$package; facts=$facts; outputs=$outputs }
}

function Resolve-EffectiveDescriptorPin([string]$Requested) {
    if (-not [string]::IsNullOrWhiteSpace($Requested)) { return $Requested.ToLowerInvariant() }
    $approved = [Environment]::GetEnvironmentVariable(
        'MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256','Process')
    if ([string]::IsNullOrWhiteSpace($approved)) { return $null }
    return $approved.ToLowerInvariant()
}

# ---- entry point -----------------------------------------------------------

if (-not [string]::IsNullOrWhiteSpace($TrustedSupervisorKeySha256)) {
    Throw-Authority 'PRODUCTION_AUTHORITY_LEGACY_V3_SUPERVISOR_PIN_REJECTED'
}
if ($Mode -ceq 'Formal' -and ($OperatorAttestsGenuineProviderEvents -or
        $OperatorAttestsNoSyntheticInjection -or $OperatorAttestsIsolatedTopology -or
        $OperatorAttestsRealProcessLedger -or $OperatorAttestsMonitorOnly -or $FixtureOnly)) {
    Throw-Authority 'PRODUCTION_AUTHORITY_CALLER_BOOLEAN_PROMOTION_REJECTED'
}
if ([string]::IsNullOrWhiteSpace($OpenSslPath)) {
    $OpenSslPath = [Environment]::GetEnvironmentVariable('MCACE_RELEASE_AUTHORITY_OPENSSL_PATH','Process')
}
if ([string]::IsNullOrWhiteSpace($ExpectedOpenSslSha256)) {
    $ExpectedOpenSslSha256 = [Environment]::GetEnvironmentVariable(
        'MCACE_RELEASE_AUTHORITY_OPENSSL_SHA256','Process')
}
$tool = Resolve-TrustedOpenSsl $OpenSslPath $ExpectedOpenSslSha256
$pin = Resolve-EffectiveDescriptorPin $ExpectedCaptureSupervisorPublicDescriptorSha256

if (-not [string]::IsNullOrWhiteSpace($ValidatePackageRoot)) {
    if (-not [string]::IsNullOrWhiteSpace($CaptureManifestPath) -or
            -not [string]::IsNullOrWhiteSpace($OutputDirectory) -or
            -not [string]::IsNullOrWhiteSpace($CaptureSupervisorPublicDescriptorPath) -or
            -not [string]::IsNullOrWhiteSpace($SupervisorSigningRequestPath) -or
            -not [string]::IsNullOrWhiteSpace($SupervisorReceiptPath) -or $Mode -cne 'Formal') {
        Throw-Authority 'PRODUCTION_AUTHORITY_VALIDATE_PACKAGE_PARAMETER_SET_INVALID'
    }
    if ([string]::IsNullOrWhiteSpace($pin) -or [string]::IsNullOrWhiteSpace($ReleaseBundleRoot)) {
        Throw-Authority 'PRODUCTION_AUTHORITY_VALIDATE_PACKAGE_PIN_AND_BUNDLE_REQUIRED'
    }
    $validated = Invoke-ValidatePublishedPackage $ValidatePackageRoot $pin $tool $ReleaseBundleRoot `
        ([bool]$RequireCurrentlyValidReceipt)
    Write-Output (('PRODUCTION_AUTHORITY_V4_PACKAGE_VALIDATION_PASS|capture_id={0}' +
        '|operation_attempt_id={1}|raw_root={2}|provider_commitment={3}') -f
        [string]$validated.facts.raw_set.capture.capture_id,
        [string]$validated.facts.raw_set.capture.operation_attempt_id,
        [string]$validated.facts.raw_root,[string]$validated.facts.provider_commitment)
    return
}

if ([string]::IsNullOrWhiteSpace($CaptureManifestPath) -or
        [string]::IsNullOrWhiteSpace($OutputDirectory) -or
        [string]::IsNullOrWhiteSpace($CaptureSupervisorPublicDescriptorPath) -or
        [string]::IsNullOrWhiteSpace($ReleaseBundleRoot) -or [string]::IsNullOrWhiteSpace($pin)) {
    Throw-Authority 'PRODUCTION_AUTHORITY_V4_INPUTS_REQUIRED'
}
if ($Mode -ceq 'Formal' -and ([string]::IsNullOrWhiteSpace($SupervisorSigningRequestPath) -or
        [string]::IsNullOrWhiteSpace($SupervisorReceiptPath))) {
    Throw-Authority 'PRODUCTION_AUTHORITY_FORMAL_SIGNING_HANDOFF_REQUIRED'
}
if ($Mode -ceq 'Fixture' -and ([string]::IsNullOrWhiteSpace($SupervisorReceiptPath) -or
        -not [string]::IsNullOrWhiteSpace($SupervisorSigningRequestPath))) {
    Throw-Authority 'PRODUCTION_AUTHORITY_FIXTURE_IMMEDIATE_RECEIPT_REQUIRED'
}
if ($RequireCurrentlyValidReceipt) {
    Throw-Authority 'PRODUCTION_AUTHORITY_CURRENT_RECEIPT_SWITCH_VALIDATE_ONLY'
}
$captureAbsolute = [IO.Path]::GetFullPath($CaptureManifestPath)
$descriptorAbsolute = [IO.Path]::GetFullPath($CaptureSupervisorPublicDescriptorPath)
$receiptAbsolute = [IO.Path]::GetFullPath($SupervisorReceiptPath)
if ($Mode -ceq 'Formal') {
    $repoPrefix = $script:RepoRoot.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    $requestAbsolute = [IO.Path]::GetFullPath($SupervisorSigningRequestPath)
    foreach ($external in @($descriptorAbsolute,$requestAbsolute,$receiptAbsolute)) {
        if ($external.StartsWith($repoPrefix,[StringComparison]::OrdinalIgnoreCase)) {
            Throw-Authority 'PRODUCTION_AUTHORITY_EXTERNAL_SUPERVISOR_INPUT_INSIDE_REPOSITORY'
        }
    }
}
$rawSet = Read-RawCaptureSet $captureAbsolute
$descriptorDocument = Read-JsonDocument $descriptorAbsolute 'capture-supervisor-public-descriptor'
$outputParent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($OutputDirectory))
if ([string]::IsNullOrWhiteSpace($outputParent) -or -not [IO.Directory]::Exists($outputParent)) {
    Throw-Authority 'PRODUCTION_AUTHORITY_OUTPUT_PARENT_REQUIRED'
}
$outputAbsolute = [IO.Path]::GetFullPath($OutputDirectory)
Assert-PathChainNoReparse $outputAbsolute $false
if ([IO.File]::Exists($outputAbsolute) -or [IO.Directory]::Exists($outputAbsolute)) {
    Throw-Authority 'PRODUCTION_AUTHORITY_OUTPUT_ALREADY_EXISTS'
}
$formal = $Mode -ceq 'Formal'
if ($formal) {
    $exchange = Assert-ExternalExchangePaths $requestAbsolute $receiptAbsolute $descriptorAbsolute `
        $ReleaseBundleRoot $outputAbsolute
    $facts = Invoke-AuthorityRawPrevalidation $rawSet $descriptorDocument $pin $tool `
        $ReleaseBundleRoot $outputParent $true $true
    $signingRequest = New-AuthoritySigningRequest $facts $exchange.request $exchange.receipt $pin `
        $SupervisorReceiptValiditySeconds
    Write-Output (('PRODUCTION_AUTHORITY_SIGNING_REQUEST_READY|request={0}|receipt={1}' +
        '|attempt={2}|challenge={3}') -f $exchange.request,$exchange.receipt,
        [string]$rawSet.capture.operation_attempt_id,[string]$signingRequest.challenge_sha256)
    $receiptDocument = Wait-AuthoritySupervisorReceipt $exchange.receipt `
        $SupervisorReceiptWaitSeconds $signingRequest
    $facts = Complete-AuthorityReceiptValidation $facts $receiptDocument $tool $outputParent `
        $true $true $signingRequest.payload_bytes
    Assert-AuthoritySigningRequestStable $signingRequest
} else {
    $receiptDocument = Read-JsonDocument $receiptAbsolute 'supervisor-receipt'
    $facts = Invoke-AuthorityRawValidation $rawSet $descriptorDocument $receiptDocument $pin $tool `
        $ReleaseBundleRoot $outputParent $false $false
}
$final = Write-AuthorityPackage $facts $OutputDirectory $formal
Write-Output (('PRODUCTION_AUTHORITY_PROCESS_EVIDENCE_V4_PASS|mode={0}|release_eligible=false' +
    '|capture_id={1}|operation_attempt_id={2}|output={3}') -f
    $Mode,[string]$rawSet.capture.capture_id,[string]$rawSet.capture.operation_attempt_id,$final)
