[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RequestPath,
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedRequestSha256,
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ApprovedRequestSha256,
    [Parameter(Mandatory)][string]$ReceiptPath,
    [Parameter(Mandatory)][string]$ExpectedDescriptorPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedDescriptorSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedSignerKeyIdSha256,
    [Parameter(Mandatory)][string]$PrivateKeyPath,
    [Parameter(Mandatory)][string]$OpenSslPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedOpenSslSha256,
    [Parameter(Mandatory)][string]$OpenSslRuntimeManifestPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedOpenSslRuntimeManifestSha256,
    [Parameter(Mandatory)][string]$AllowedExchangeRoot,
    [switch]$TestFixture
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $script:PSNativeCommandUseErrorActionPreference = $false
}

$script:SignerRepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$script:SignerUtf8Strict = New-Object Text.UTF8Encoding($false, $true)
$script:SignerUtf8NoBom = New-Object Text.UTF8Encoding($false)
$script:SignerIsWindows = if (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) {
    [bool]$IsWindows
} else { [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT }

function Throw-AuthoritySigner([string]$Code) { throw $Code }

function Get-AuthoritySignerSha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
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

function Test-AuthoritySignerBytesEqual([byte[]]$Left, [byte[]]$Right) {
    return [MCAceConstantTimeByteEqualityV1]::Equals($Left, $Right)
}

function Test-AuthoritySignerExactProperties([object]$Value, [string[]]$Expected) {
    if ($null -eq $Value -or $Value -isnot [Management.Automation.PSCustomObject]) {
        return $false
    }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    return $actual.Count -eq $wanted.Count -and (($actual -join "`n") -ceq ($wanted -join "`n"))
}

function Get-AuthoritySignerJsonPropertyCount([object]$Value) {
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return 0 }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $properties = @($Value.PSObject.Properties)
        $count = $properties.Count
        foreach ($property in $properties) {
            $count += Get-AuthoritySignerJsonPropertyCount $property.Value
        }
        return $count
    }
    if ($Value -is [Collections.IDictionary]) {
        $count = @($Value.Keys).Count
        foreach ($key in @($Value.Keys)) { $count += Get-AuthoritySignerJsonPropertyCount $Value[$key] }
        return $count
    }
    if ($Value -is [Collections.IEnumerable]) {
        $count = 0
        foreach ($entry in $Value) { $count += Get-AuthoritySignerJsonPropertyCount $entry }
        return $count
    }
    return 0
}

function Test-AuthoritySignerJsonInteger([object]$Value) {
    return $Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64]
}

function Assert-AuthoritySignerSha256([object]$Value, [string]$Name) {
    if ($Value -isnot [string] -or [string]$Value -cnotmatch '^[0-9a-f]{64}$') {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_SHA256_INVALID|$Name"
    }
}

function Assert-AuthoritySignerString([object]$Value, [string]$Name) {
    if ($Value -isnot [string]) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_STRING_TYPE_INVALID|$Name"
    }
}

function Assert-AuthoritySignerGuid([object]$Value, [string]$Name) {
    $parsed = [guid]::Empty
    if ($Value -isnot [string] -or
            -not [guid]::TryParseExact([string]$Value, 'D', [ref]$parsed) -or
            $parsed.ToString('D') -cne [string]$Value) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_GUID_INVALID|$Name"
    }
}

function ConvertFrom-AuthoritySignerUtc([object]$Value, [string]$Name) {
    if ($Value -isnot [string] -or
            [string]$Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$') {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_TIMESTAMP_INVALID|$Name"
    }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            [string]$Value,
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$parsed)) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_TIMESTAMP_INVALID|$Name"
    }
    return $parsed.ToUniversalTime()
}

function ConvertFrom-AuthoritySignerBase64(
        [object]$Value, [int]$Minimum, [int]$Maximum, [string]$Name) {
    if ($Value -isnot [string]) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_BASE64_INVALID|$Name"
    }
    try { [byte[]]$bytes = [Convert]::FromBase64String([string]$Value) }
    catch { Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_BASE64_INVALID|$Name" }
    if ($bytes.Length -lt $Minimum -or $bytes.Length -gt $Maximum -or
            [Convert]::ToBase64String($bytes) -cne [string]$Value) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_BASE64_INVALID|$Name"
    }
    return ,$bytes
}

function Test-AuthoritySignerPathUnderRoot([string]$Path, [string]$Root) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\','/')
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\','/')
    return $full.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase) -or
        $full.StartsWith($rootFull + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)
}

function Initialize-AuthoritySignerIdentityApi {
    if (-not $script:SignerIsWindows) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_WINDOWS_REQUIRED'
    }
    if ('MCAceProductionAuthoritySignerFileIdentityV1' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class MCAceProductionAuthoritySignerFileIdentityV1 {
    private const uint FILE_READ_ATTRIBUTES = 0x80;
    private const uint FILE_LIST_DIRECTORY = 0x1;
    private const uint FILE_ADD_FILE = 0x2;
    private const uint FILE_SHARE_READ = 1;
    private const uint FILE_SHARE_WRITE = 2;
    private const uint FILE_SHARE_DELETE = 4;
    private const uint OPEN_EXISTING = 3;
    private const uint SYNCHRONIZE = 0x00100000;
    private const uint DELETE_ACCESS = 0x00010000;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    private const uint FILE_CREATE = 2;
    private const uint FILE_NON_DIRECTORY_FILE = 0x40;
    private const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x20;
    private const uint OBJ_CASE_INSENSITIVE = 0x40;
    private const int FILE_DISPOSITION_INFO_CLASS = 4;
    private const int FILE_RENAME_INFORMATION_CLASS = 10;

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_ATTRIBUTES {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_STATUS_BLOCK {
        public IntPtr Status;
        public UIntPtr Information;
    }

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle handle, int informationClass, IntPtr information, uint size);

    [DllImport("ntdll.dll")]
    private static extern int NtCreateFile(
        out IntPtr fileHandle, uint desiredAccess, ref OBJECT_ATTRIBUTES attributes,
        out IO_STATUS_BLOCK statusBlock, IntPtr allocationSize, uint fileAttributes,
        uint shareAccess, uint createDisposition, uint createOptions,
        IntPtr eaBuffer, uint eaLength);

    [DllImport("ntdll.dll")]
    private static extern uint RtlNtStatusToDosError(int status);

    [DllImport("ntdll.dll")]
    private static extern int NtSetInformationFile(
        SafeFileHandle fileHandle, out IO_STATUS_BLOCK statusBlock,
        IntPtr fileInformation, uint length, int fileInformationClass);

    private static string Describe(BY_HANDLE_FILE_INFORMATION info) {
        return info.VolumeSerialNumber.ToString("x8") + ":" +
            info.FileIndexHigh.ToString("x8") + info.FileIndexLow.ToString("x8");
    }

    private static BY_HANDLE_FILE_INFORMATION ReadInfo(SafeFileHandle handle) {
        BY_HANDLE_FILE_INFORMATION info;
        if (!GetFileInformationByHandle(handle, out info))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if ((info.Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            throw new InvalidOperationException("reparse point rejected");
        return info;
    }

    public static SafeFileHandle OpenPinnedDirectory(string path, bool writable) {
        uint access = FILE_READ_ATTRIBUTES | SYNCHRONIZE |
            (writable ? (FILE_LIST_DIRECTORY | FILE_ADD_FILE) : 0u);
        SafeFileHandle handle = CreateFileW(path, access,
            FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (handle.IsInvalid) {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error);
        }
        try {
            BY_HANDLE_FILE_INFORMATION info = ReadInfo(handle);
            if ((info.Attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                throw new InvalidOperationException("directory required");
            return handle;
        } catch {
            handle.Dispose();
            throw;
        }
    }

    private static SafeFileHandle CreateRelativeExclusive(
        SafeFileHandle root, string leaf) {
        if (root == null || root.IsInvalid || root.IsClosed)
            throw new InvalidOperationException("stable root handle required");
        if (String.IsNullOrEmpty(leaf) || leaf.IndexOfAny(new char[] {'\\','/','\0'}) >= 0)
            throw new InvalidOperationException("single relative leaf required");
        IntPtr text = IntPtr.Zero;
        IntPtr namePointer = IntPtr.Zero;
        try {
            text = Marshal.StringToHGlobalUni(leaf);
            UNICODE_STRING name = new UNICODE_STRING();
            name.Length = checked((ushort)(leaf.Length * 2));
            name.MaximumLength = checked((ushort)(name.Length + 2));
            name.Buffer = text;
            namePointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
            Marshal.StructureToPtr(name, namePointer, false);
            OBJECT_ATTRIBUTES attributes = new OBJECT_ATTRIBUTES();
            attributes.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
            attributes.RootDirectory = root.DangerousGetHandle();
            attributes.ObjectName = namePointer;
            attributes.Attributes = OBJ_CASE_INSENSITIVE;
            IO_STATUS_BLOCK statusBlock;
            IntPtr raw;
            int status = NtCreateFile(out raw,
                GENERIC_READ | GENERIC_WRITE | DELETE_ACCESS | SYNCHRONIZE,
                ref attributes, out statusBlock, IntPtr.Zero, FILE_ATTRIBUTE_NORMAL,
                0u, FILE_CREATE,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
                    FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero, 0u);
            if (status < 0)
                throw new Win32Exception((int)RtlNtStatusToDosError(status));
            return new SafeFileHandle(raw, true);
        } finally {
            if (namePointer != IntPtr.Zero) Marshal.FreeHGlobal(namePointer);
            if (text != IntPtr.Zero) Marshal.FreeHGlobal(text);
        }
    }

    private static void MarkDeleteOnClose(SafeFileHandle handle) {
        IntPtr value = Marshal.AllocHGlobal(1);
        try {
            Marshal.WriteByte(value, 1);
            SetFileInformationByHandle(handle, FILE_DISPOSITION_INFO_CLASS, value, 1u);
        } finally { Marshal.FreeHGlobal(value); }
    }

    private static void RenameRelative(
        SafeFileHandle file, SafeFileHandle root, string leaf) {
        byte[] name = System.Text.Encoding.Unicode.GetBytes(leaf);
        int rootOffset = IntPtr.Size == 8 ? 8 : 4;
        int lengthOffset = rootOffset + IntPtr.Size;
        int nameOffset = lengthOffset + 4;
        int bufferSize = checked(nameOffset + name.Length);
        IntPtr value = Marshal.AllocHGlobal(bufferSize);
        try {
            for (int i = 0; i < bufferSize; i++) Marshal.WriteByte(value, i, 0);
            Marshal.WriteByte(value, 0, 0);
            Marshal.WriteIntPtr(value, rootOffset, root.DangerousGetHandle());
            Marshal.WriteInt32(value, lengthOffset, name.Length);
            Marshal.Copy(name, 0, IntPtr.Add(value, nameOffset), name.Length);
            IO_STATUS_BLOCK statusBlock;
            int status = NtSetInformationFile(file, out statusBlock, value,
                checked((uint)bufferSize), FILE_RENAME_INFORMATION_CLASS);
            if (status < 0)
                throw new Win32Exception((int)RtlNtStatusToDosError(status));
        } finally { Marshal.FreeHGlobal(value); }
    }

    public static string WriteAtomicRelative(
        SafeFileHandle root, string temporaryLeaf, string finalLeaf, byte[] bytes) {
        if (bytes == null || bytes.Length == 0)
            throw new InvalidOperationException("output bytes required");
        SafeFileHandle handle = CreateRelativeExclusive(root, temporaryLeaf);
        FileStream stream = null;
        try {
            string installedIdentity;
            stream = new FileStream(handle, FileAccess.ReadWrite, 4096, false);
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush(true);
            stream.Position = 0;
            byte[] check = new byte[bytes.Length];
            int offset = 0;
            while (offset < check.Length) {
                int read = stream.Read(check, offset, check.Length - offset);
                if (read <= 0) throw new EndOfStreamException();
                offset += read;
            }
            if (stream.ReadByte() != -1) throw new IOException("output grew during readback");
            int difference = 0;
            for (int i = 0; i < bytes.Length; i++) difference |= bytes[i] ^ check[i];
            if (difference != 0) throw new IOException("output readback mismatch");
            BY_HANDLE_FILE_INFORMATION beforeRename = ReadInfo(handle);
            if ((beforeRename.Attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
                beforeRename.NumberOfLinks != 1)
                throw new IOException("regular single-link output required");
            RenameRelative(handle, root, finalLeaf);
            stream.Flush(true);
            installedIdentity = Describe(ReadInfo(handle));
            return installedIdentity;
        } catch {
            try { MarkDeleteOnClose(handle); } catch { }
            throw;
        } finally {
            if (stream != null) stream.Dispose();
            else handle.Dispose();
        }
    }

    public static string NoFollow(string path, bool directory) {
        uint flags = FILE_FLAG_OPEN_REPARSE_POINT |
            (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0u);
        using (SafeFileHandle handle = CreateFileW(path, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero,
            OPEN_EXISTING, flags, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(handle, out info))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((info.Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                throw new InvalidOperationException("reparse point rejected");
            if (!directory && (info.Attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
                info.NumberOfLinks != 1)
                throw new InvalidOperationException("hard-linked file rejected");
            return Describe(info);
        }
    }

    public static string FromHandle(SafeFileHandle handle) {
        BY_HANDLE_FILE_INFORMATION info = ReadInfo(handle);
        if ((info.Attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 && info.NumberOfLinks != 1)
            throw new InvalidOperationException("hard-linked file rejected");
        return Describe(info);
    }
}
'@
}

function Get-AuthoritySignerNoFollowIdentity([string]$Path, [switch]$Directory) {
    Initialize-AuthoritySignerIdentityApi
    try {
        return [MCAceProductionAuthoritySignerFileIdentityV1]::NoFollow(
            [IO.Path]::GetFullPath($Path), [bool]$Directory)
    } catch {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_NOFOLLOW_IDENTITY_FAILED|$($_.Exception.Message)"
    }
}

function Assert-AuthoritySignerNoReparseChain(
        [string]$Path, [bool]$LeafMustExist, [string]$Role) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_ABSOLUTE_PATH_REQUIRED|$Role"
    }
    if ($Path -match '[\x00-\x1f]') {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_PATH_CONTROL_CHARACTER_REJECTED|$Role"
    }
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root)) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_PATH_ROOT_INVALID|$Role"
    }
    [char[]]$separators = @([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $segments = @($full.Substring($root.Length).Split(
        $separators, [StringSplitOptions]::RemoveEmptyEntries))
    $cursor = $root
    for ($index = 0; $index -lt $segments.Count; $index++) {
        $cursor = Join-Path $cursor $segments[$index]
        $exists = [IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)
        if (-not $exists) {
            if ($LeafMustExist -or $index -lt ($segments.Count - 1)) {
                Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_PATH_COMPONENT_MISSING|$Role"
            }
            return $full
        }
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_REPARSE_PATH_REJECTED|$Role"
        }
        $isDirectory = [IO.Directory]::Exists($cursor)
        $null = Get-AuthoritySignerNoFollowIdentity $cursor -Directory:$isDirectory
    }
    return $full
}

function Get-AuthoritySignerDirectoryComponents([string]$DirectoryPath) {
    $full = [IO.Path]::GetFullPath($DirectoryPath).TrimEnd('\','/')
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root)) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_PATH_ROOT_INVALID|stable-directory-chain'
    }
    $components = New-Object Collections.Generic.List[string]
    $components.Add($root.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar)
    [char[]]$separators = @([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $cursor = $root
    foreach ($segment in @($full.Substring($root.Length).Split(
                $separators, [StringSplitOptions]::RemoveEmptyEntries))) {
        $cursor = Join-Path $cursor $segment
        $components.Add([IO.Path]::GetFullPath($cursor))
    }
    return @($components)
}

function Open-AuthoritySignerStableDirectoryChain([string]$DirectoryPath) {
    Initialize-AuthoritySignerIdentityApi
    $absolute = Assert-AuthoritySignerNoReparseChain $DirectoryPath $true 'stable-exchange-root'
    if (-not [IO.Directory]::Exists($absolute) -or [IO.File]::Exists($absolute)) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_STABLE_DIRECTORY_REQUIRED'
    }
    $handles = New-Object Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]
    $identities = New-Object Collections.Generic.List[string]
    try {
        $components = @(Get-AuthoritySignerDirectoryComponents $absolute)
        for ($index = 0; $index -lt $components.Count; $index++) {
            $writable = $index -eq ($components.Count - 1)
            $handle = [MCAceProductionAuthoritySignerFileIdentityV1]::OpenPinnedDirectory(
                [string]$components[$index], $writable)
            $identity = [MCAceProductionAuthoritySignerFileIdentityV1]::FromHandle($handle)
            $pathIdentity = Get-AuthoritySignerNoFollowIdentity $components[$index] -Directory
            if ($identity -cne $pathIdentity) {
                $handle.Dispose()
                Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_STABLE_DIRECTORY_IDENTITY_MISMATCH'
            }
            $handles.Add($handle)
            $identities.Add($identity)
        }
        return [pscustomobject]@{
            path=$absolute
            components=$components
            handles=@($handles)
            identities=@($identities)
            root_handle=$handles[$handles.Count - 1]
            root_identity=$identities[$identities.Count - 1]
        }
    } catch {
        for ($index = $handles.Count - 1; $index -ge 0; $index--) {
            $handles[$index].Dispose()
        }
        throw
    }
}

function Assert-AuthoritySignerStableDirectoryChain([object]$Anchor, [string]$Stage) {
    for ($index = 0; $index -lt @($Anchor.handles).Count; $index++) {
        $handleIdentity = [MCAceProductionAuthoritySignerFileIdentityV1]::FromHandle(
            $Anchor.handles[$index])
        $pathIdentity = Get-AuthoritySignerNoFollowIdentity $Anchor.components[$index] -Directory
        if ($handleIdentity -cne [string]$Anchor.identities[$index] -or
                $pathIdentity -cne [string]$Anchor.identities[$index]) {
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_STABLE_DIRECTORY_CHANGED|$Stage"
        }
    }
}

function Close-AuthoritySignerStableDirectoryChain([object]$Anchor) {
    if ($null -eq $Anchor) { return }
    for ($index = @($Anchor.handles).Count - 1; $index -ge 0; $index--) {
        $Anchor.handles[$index].Dispose()
    }
}

function Read-AuthoritySignerExact(
        [IO.FileStream]$Stream, [int]$Length, [string]$Role) {
    [byte[]]$bytes = New-Object byte[] $Length
    $offset = 0
    while ($offset -lt $Length) {
        $read = $Stream.Read($bytes, $offset, $Length - $offset)
        if ($read -le 0) {
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_SHORT_READ|$Role"
        }
        $offset += $read
    }
    if ($Stream.ReadByte() -ne -1) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_GROWTH_DURING_READ|$Role"
    }
    return ,$bytes
}

function Read-AuthoritySignerLockedFile(
        [string]$Path, [long]$Minimum, [long]$Maximum, [string]$Role) {
    $absolute = Assert-AuthoritySignerNoReparseChain $Path $true $Role
    $item = Get-Item -LiteralPath $absolute -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_REGULAR_FILE_REQUIRED|$Role"
    }
    $before = Get-AuthoritySignerNoFollowIdentity $absolute
    $stream = New-Object IO.FileStream(
        $absolute, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        $length = [long]$stream.Length
        if ($length -lt $Minimum -or $length -gt $Maximum -or $length -gt [int]::MaxValue) {
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_FILE_SIZE_INVALID|$Role"
        }
        $handleIdentity = [MCAceProductionAuthoritySignerFileIdentityV1]::FromHandle(
            $stream.SafeFileHandle)
        if ($handleIdentity -cne $before) {
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_HANDLE_IDENTITY_CHANGED|$Role"
        }
        [byte[]]$first = Read-AuthoritySignerExact $stream ([int]$length) "$Role|first"
        $stream.Position = 0
        [byte[]]$second = Read-AuthoritySignerExact $stream ([int]$length) "$Role|second"
        if (-not (Test-AuthoritySignerBytesEqual $first $second)) {
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_DOUBLE_READ_MISMATCH|$Role"
        }
    } finally { $stream.Dispose() }
    $after = Get-AuthoritySignerNoFollowIdentity $absolute
    if ($after -cne $before) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_PATH_IDENTITY_CHANGED|$Role"
    }
    return [pscustomobject]@{
        path=$absolute
        bytes=$first
        sha256=(Get-AuthoritySignerSha256 $first)
        size_bytes=[long]$first.Length
        identity=$before
    }
}

function ConvertFrom-AuthoritySignerJsonDocument([object]$Document, [string]$Role) {
    [byte[]]$bytes = [byte[]]$Document.bytes
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and
            $bytes[1] -eq 0xbb -and $bytes[2] -eq 0xbf) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_JSON_BOM_REJECTED|$Role"
    }
    try { $raw = $script:SignerUtf8Strict.GetString($bytes) }
    catch { Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_JSON_UTF8_INVALID|$Role" }
    if ($raw.Contains("`r")) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_JSON_CR_REJECTED|$Role"
    }
    try {
        $command = Get-Command ConvertFrom-Json -CommandType Cmdlet
        if ($command.Parameters.ContainsKey('DateKind')) {
            $value = ConvertFrom-Json -InputObject $raw -DateKind String -ErrorAction Stop
        } else {
            $value = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
        }
    } catch {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_JSON_INVALID|$Role"
    }
    if ($null -eq $value -or $value -isnot [Management.Automation.PSCustomObject]) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_JSON_OBJECT_REQUIRED|$Role"
    }
    $propertyTokens = [regex]::Matches(
        $raw, '(?:\{|,)\s*"(?:\\["\\/bfnrt]|\\u[0-9a-fA-F]{4}|[^"\\])*"\s*:').Count
    if ($propertyTokens -ne (Get-AuthoritySignerJsonPropertyCount $value)) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_DUPLICATE_OR_AMBIGUOUS_PROPERTY|$Role"
    }
    return [pscustomobject]@{ value=$value; raw=$raw }
}

function Assert-AuthoritySignerStableDocument(
        [string]$Path, [object]$Original, [long]$Minimum, [long]$Maximum, [string]$Role) {
    $current = Read-AuthoritySignerLockedFile $Path $Minimum $Maximum $Role
    if ($current.sha256 -cne [string]$Original.sha256 -or
            $current.size_bytes -ne [long]$Original.size_bytes -or
            $current.identity -cne [string]$Original.identity -or
            -not (Test-AuthoritySignerBytesEqual $current.bytes $Original.bytes)) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_INPUT_MUTATED|$Role"
    }
}

function Assert-AuthoritySignerPrivateDirectoryAcl([string]$Path, [string]$Role) {
    if (-not $script:SignerIsWindows) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_WINDOWS_REQUIRED'
    }
    $absolute = Assert-AuthoritySignerNoReparseChain $Path $true $Role
    if (-not [IO.Directory]::Exists($absolute) -or [IO.File]::Exists($absolute)) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_PRIVATE_DIRECTORY_REQUIRED|$Role"
    }
    $acl = Get-Acl -LiteralPath $absolute -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_PRIVATE_DIRECTORY_ACL_INHERITANCE_REJECTED|$Role"
    }
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    try { $owner = (New-Object Security.Principal.NTAccount($acl.Owner)).Translate(
            [Security.Principal.SecurityIdentifier]) }
    catch { Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_PRIVATE_DIRECTORY_OWNER_INVALID|$Role" }
    if ($owner -ne $current -and $owner -ne $system) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_PRIVATE_DIRECTORY_OWNER_INVALID|$Role"
    }
    $approved = @($current.Value, $system.Value)
    $fullControl = [Security.AccessControl.FileSystemRights]::FullControl
    $fullControlSids = New-Object Collections.Generic.HashSet[string]([StringComparer]::Ordinal)
    foreach ($rule in @($acl.GetAccessRules($true, $true,
                [Security.Principal.SecurityIdentifier]))) {
        if ($rule.IsInherited -or $rule.IdentityReference.Value -cnotin $approved -or
                $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_PRIVATE_DIRECTORY_ACL_PRINCIPAL_REJECTED|$Role"
        }
        if (($rule.FileSystemRights -band $fullControl) -eq $fullControl) {
            $null = $fullControlSids.Add($rule.IdentityReference.Value)
        }
    }
    if (-not $fullControlSids.Contains($current.Value) -or
            -not $fullControlSids.Contains($system.Value)) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_PRIVATE_DIRECTORY_ACL_INCOMPLETE|$Role"
    }
    return $absolute
}

function Get-AuthoritySignerRuntimeRelativePath([string]$Root, [string]$Path) {
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\','/')
    $pathFull = [IO.Path]::GetFullPath($Path)
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    if (-not $pathFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_RUNTIME_PATH_OUTSIDE_ROOT'
    }
    return $pathFull.Substring($prefix.Length).Replace('\','/')
}

function Sort-AuthoritySignerRuntimeItemsOrdinal([object[]]$Items) {
    $sorted = New-Object Collections.ArrayList
    foreach ($item in @($Items)) {
        $insertAt = 0
        while ($insertAt -lt $sorted.Count -and
                [StringComparer]::Ordinal.Compare(
                    [string]$sorted[$insertAt].relative_path,
                    [string]$item.relative_path) -lt 0) {
            $insertAt++
        }
        $sorted.Insert($insertAt, $item)
    }
    return @($sorted.ToArray())
}

function Get-AuthoritySignerRuntimeFileSet([string]$Root) {
    $files = @()
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Recurse -Force -File)) {
        $null = Assert-AuthoritySignerNoReparseChain $item.FullName $true 'openssl-runtime-file'
        $relative = Get-AuthoritySignerRuntimeRelativePath $Root $item.FullName
        $files += [pscustomobject]@{ relative_path=$relative; path=$item.FullName }
    }
    return @(Sort-AuthoritySignerRuntimeItemsOrdinal $files)
}

function Resolve-AuthoritySignerOpenSslRuntime(
        [string]$ManifestPath, [string]$ExpectedManifestSha256,
        [string]$ExecutablePath, [string]$ExpectedExecutableSha256) {
    $manifestDocument = Read-AuthoritySignerLockedFile $ManifestPath 64 4194304 `
        'openssl-runtime-manifest'
    if ($manifestDocument.sha256 -cne $ExpectedManifestSha256.ToLowerInvariant()) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_MANIFEST_SHA256_MISMATCH'
    }
    $manifestJson = ConvertFrom-AuthoritySignerJsonDocument $manifestDocument `
        'openssl-runtime-manifest'
    $manifest = $manifestJson.value
    if (-not (Test-AuthoritySignerExactProperties $manifest @(
            'schema','artifact_class','platform','executable_relative_path','files','test_fixture')) -or
            $manifest.schema -cne 'MCACE_OPENSSL_RUNTIME_MANIFEST_V1' -or
            $manifest.artifact_class -cne 'REVIEWED_OPENSSL_RUNTIME' -or
            $manifest.platform -cne 'windows-x64' -or
            $manifest.executable_relative_path -isnot [string] -or
            $manifest.files -isnot [Array] -or
            $manifest.test_fixture -isnot [bool] -or
            -not [Environment]::Is64BitProcess) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_MANIFEST_SCHEMA_INVALID'
    }
    if ([bool]$manifest.test_fixture -ne [bool]$TestFixture) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_MANIFEST_FIXTURE_MISMATCH'
    }
    $executableRelative = [string]$manifest.executable_relative_path
    if ($executableRelative -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.exe$') {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_EXECUTABLE_LEAF_INVALID'
    }
    $runtimeRoot = Assert-AuthoritySignerPrivateDirectoryAcl `
        ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ExecutablePath))) 'openssl-runtime-root'
    $manifestAbsolute = [IO.Path]::GetFullPath($manifestDocument.path)
    if (Test-AuthoritySignerPathUnderRoot $manifestAbsolute $runtimeRoot) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_MANIFEST_INSIDE_RUNTIME_REJECTED'
    }
    $providersRoot = Join-Path $runtimeRoot 'providers'
    $null = Assert-AuthoritySignerNoReparseChain $providersRoot $true 'openssl-providers-root'
    if (-not [IO.Directory]::Exists($providersRoot)) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_PROVIDERS_DIRECTORY_REQUIRED'
    }
    $entries = @($manifest.files)
    if ($entries.Count -lt 3 -or $entries.Count -gt 1024) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_FILE_COUNT_INVALID'
    }
    $expected = [ordered]@{}
    $previous = $null
    $executableCount = 0
    $applicationDllCount = 0
    $providerCount = 0
    $configCount = 0
    foreach ($entry in $entries) {
        if (-not (Test-AuthoritySignerExactProperties $entry @(
                'relative_path','role','size_bytes','sha256')) -or
                $entry.relative_path -isnot [string] -or $entry.role -isnot [string] -or
                -not (Test-AuthoritySignerJsonInteger $entry.size_bytes)) {
            Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_ENTRY_SCHEMA_INVALID'
        }
        $relative = [string]$entry.relative_path
        if ($relative -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+@~/-]{0,255}$' -or
                $relative.Contains('\') -or $relative.Contains('//') -or
                @($relative.Split('/') | Where-Object { $_ -in @('.','..') }).Count -ne 0) {
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_RELATIVE_PATH_INVALID|$relative"
        }
        if ($null -ne $previous -and
                [StringComparer]::Ordinal.Compare([string]$previous, $relative) -ge 0) {
            Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_ORDER_OR_DUPLICATE_INVALID'
        }
        $previous = $relative
        Assert-AuthoritySignerSha256 $entry.sha256 "openssl_runtime_$relative"
        if ([long]$entry.size_bytes -le 0 -or [long]$entry.size_bytes -gt 268435456) {
            Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_FILE_SIZE_INVALID'
        }
        switch ([string]$entry.role) {
            'EXECUTABLE' {
                if ($relative -cne $executableRelative) {
                    Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_EXECUTABLE_BINDING_INVALID'
                }
                $executableCount++
            }
            'APPLICATION_LOCAL_DLL' {
                if ($relative.Contains('/') -or [IO.Path]::GetExtension($relative) -cne '.dll') {
                    Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_DLL_LOCATION_INVALID'
                }
                $applicationDllCount++
            }
            'PROVIDER_MODULE' {
                if (-not $relative.StartsWith('providers/', [StringComparison]::Ordinal) -or
                        [IO.Path]::GetExtension($relative) -cne '.dll') {
                    Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_PROVIDER_LOCATION_INVALID'
                }
                $providerCount++
            }
            'CONFIG' {
                if ($relative -cne 'openssl.cnf') {
                    Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_CONFIG_LOCATION_INVALID'
                }
                $configCount++
            }
            default { Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_ROLE_INVALID' }
        }
        $path = Join-Path $runtimeRoot ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
        $document = Read-AuthoritySignerLockedFile $path 1 268435456 "openssl-runtime-$relative"
        if ($document.sha256 -cne [string]$entry.sha256 -or
                $document.size_bytes -ne [long]$entry.size_bytes) {
            Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_FILE_BINDING_INVALID'
        }
        $expected[$relative] = [pscustomobject]@{
            path=$document.path; bytes=$document.bytes; sha256=$document.sha256
            size_bytes=$document.size_bytes; identity=$document.identity; role=[string]$entry.role
        }
    }
    if ($executableCount -ne 1 -or $applicationDllCount -lt 1 -or
            $providerCount -lt 1 -or $configCount -ne 1) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_REQUIRED_ROLES_INVALID'
    }
    $actual = @(Get-AuthoritySignerRuntimeFileSet $runtimeRoot)
    if ($actual.Count -ne $expected.Count -or
            (($actual.relative_path -join "`n") -cne (@($expected.Keys) -join "`n"))) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_EXACT_SET_MISMATCH'
    }
    $expectedExecutable = [IO.Path]::GetFullPath((Join-Path $runtimeRoot $executableRelative))
    if (-not $expectedExecutable.Equals([IO.Path]::GetFullPath($ExecutablePath),
            [StringComparison]::OrdinalIgnoreCase) -or
            $expected[$executableRelative].sha256 -cne $ExpectedExecutableSha256.ToLowerInvariant()) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_EXECUTABLE_BINDING_INVALID'
    }
    [byte[]]$knownConfig = $script:SignerUtf8NoBom.GetBytes(
        "# MCAce pinned empty OpenSSL configuration v1`n")
    if (-not (Test-AuthoritySignerBytesEqual $knownConfig $expected['openssl.cnf'].bytes)) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_CONFIG_BYTES_INVALID'
    }
    return [pscustomobject]@{
        root=$runtimeRoot
        executable_path=$expectedExecutable
        executable_relative_path=$executableRelative
        config_path=(Join-Path $runtimeRoot 'openssl.cnf')
        providers_path=$providersRoot
        manifest=$manifestDocument
        entries=$expected
        relative_paths=@($expected.Keys)
    }
}

function Open-AuthoritySignerRuntimeLocks([object]$Runtime) {
    $anchor = Open-AuthoritySignerStableDirectoryChain $Runtime.root
    $locks = New-Object Collections.Generic.List[IO.FileStream]
    try {
        foreach ($relative in @($Runtime.relative_paths)) {
            $entry = $Runtime.entries[$relative]
            $stream = New-Object IO.FileStream(
                $entry.path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            $handleIdentity = [MCAceProductionAuthoritySignerFileIdentityV1]::FromHandle(
                $stream.SafeFileHandle)
            if ($handleIdentity -cne [string]$entry.identity -or
                    [long]$stream.Length -ne [long]$entry.size_bytes) {
                $stream.Dispose()
                Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_LOCK_IDENTITY_INVALID'
            }
            $locks.Add($stream)
        }
        return [pscustomobject]@{ anchor=$anchor; streams=@($locks) }
    } catch {
        for ($index = $locks.Count - 1; $index -ge 0; $index--) { $locks[$index].Dispose() }
        Close-AuthoritySignerStableDirectoryChain $anchor
        throw
    }
}

function Assert-AuthoritySignerRuntimeLocked([object]$Runtime, [object]$Locks, [string]$Stage) {
    Assert-AuthoritySignerStableDirectoryChain $Locks.anchor "openssl-runtime-$Stage"
    Assert-AuthoritySignerStableDocument $Runtime.manifest.path $Runtime.manifest 64 4194304 `
        "openssl-runtime-manifest-$Stage"
    $actual = @(Get-AuthoritySignerRuntimeFileSet $Runtime.root)
    if ($actual.Count -ne @($Runtime.relative_paths).Count -or
            (($actual.relative_path -join "`n") -cne (@($Runtime.relative_paths) -join "`n"))) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_EXACT_SET_CHANGED|$Stage"
    }
    for ($index = 0; $index -lt @($Runtime.relative_paths).Count; $index++) {
        $relative = [string]$Runtime.relative_paths[$index]
        $entry = $Runtime.entries[$relative]
        $stream = $Locks.streams[$index]
        if ([long]$stream.Length -ne [long]$entry.size_bytes -or
                [MCAceProductionAuthoritySignerFileIdentityV1]::FromHandle(
                    $stream.SafeFileHandle) -cne [string]$entry.identity) {
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_LOCK_CHANGED|$Stage"
        }
        $stream.Position = 0
        [byte[]]$first = Read-AuthoritySignerExact $stream ([int]$entry.size_bytes) `
            "openssl-runtime-lock-$Stage-$relative"
        $stream.Position = 0
        [byte[]]$second = Read-AuthoritySignerExact $stream ([int]$entry.size_bytes) `
            "openssl-runtime-lock2-$Stage-$relative"
        if (-not (Test-AuthoritySignerBytesEqual $first $second) -or
                (Get-AuthoritySignerSha256 $first) -cne [string]$entry.sha256) {
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_BYTES_CHANGED|$Stage"
        }
    }
}

function Close-AuthoritySignerRuntimeLocks([object]$Locks) {
    if ($null -eq $Locks) { return }
    for ($index = @($Locks.streams).Count - 1; $index -ge 0; $index--) {
        $Locks.streams[$index].Dispose()
    }
    Close-AuthoritySignerStableDirectoryChain $Locks.anchor
}

function ConvertTo-AuthoritySignerWindowsArgument([string]$Value) {
    if ($null -eq $Value -or $Value -match '[\x00-\x1f]') {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_ARGUMENT_INVALID'
    }
    if ($Value.Length -gt 32760) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_ARGUMENT_TOO_LONG'
    }
    if ($Value -notmatch '[\s"]') { return $Value }
    $builder = New-Object Text.StringBuilder
    $null = $builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashes++
            continue
        }
        if ($character -eq '"') {
            $null = $builder.Append(('\' * (($slashes * 2) + 1)))
            $null = $builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) { $null = $builder.Append(('\' * $slashes)); $slashes = 0 }
        $null = $builder.Append($character)
    }
    if ($slashes -gt 0) { $null = $builder.Append(('\' * ($slashes * 2))) }
    $null = $builder.Append('"')
    return $builder.ToString()
}

function Invoke-AuthoritySignerOpenSsl(
        [object]$Tool, [string[]]$Arguments, [string]$Operation) {
    Assert-AuthoritySignerRuntimeLocked $Tool.runtime $Tool.runtime_locks "pre-$Operation"
    $process = $null
    try {
        $start = New-Object Diagnostics.ProcessStartInfo
        $start.FileName = [string]$Tool.path
        $start.WorkingDirectory = [string]$Tool.runtime.root
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $quotedArguments = @($Arguments | ForEach-Object {
                ConvertTo-AuthoritySignerWindowsArgument ([string]$_
                )
            })
        $start.Arguments = $quotedArguments -join ' '
        $start.EnvironmentVariables.Clear()
        foreach ($name in @('SystemRoot','WINDIR','TEMP','TMP')) {
            $value = [Environment]::GetEnvironmentVariable($name, 'Process')
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $start.EnvironmentVariables[$name] = $value
            }
        }
        $start.EnvironmentVariables['PATH'] = [string]$Tool.runtime.root + ';' +
            (Join-Path $env:SystemRoot 'System32')
        $start.EnvironmentVariables['OPENSSL_CONF'] = [string]$Tool.runtime.config_path
        $start.EnvironmentVariables['OPENSSL_MODULES'] = [string]$Tool.runtime.providers_path
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $start
        if (-not $process.Start()) {
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_OPENSSL_START_FAILED|$Operation"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(60000)) {
            try { $process.Kill() } catch {}
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_OPENSSL_TIMEOUT|$Operation"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
    } finally {
        if ($null -ne $process) { $process.Dispose() }
        Assert-AuthoritySignerRuntimeLocked $Tool.runtime $Tool.runtime_locks "post-$Operation"
    }
    if ($exitCode -ne 0) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_OPENSSL_OPERATION_FAILED|$Operation"
    }
    return @((@($stdout,$stderr) -join "`n") -split "`r?`n" |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Write-AuthoritySignerCreateNewFile(
        [string]$Path, [byte[]]$Bytes, [string]$Role) {
    if ($null -eq $Bytes -or $Bytes.Length -le 0) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_OUTPUT_BYTES_REQUIRED|$Role"
    }
    $absolute = Assert-AuthoritySignerNoReparseChain $Path $false $Role
    $parent = [IO.Path]::GetDirectoryName($absolute)
    $null = Assert-AuthoritySignerNoReparseChain $parent $true "$Role-parent"
    if ([IO.File]::Exists($absolute) -or [IO.Directory]::Exists($absolute)) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_OUTPUT_ALREADY_EXISTS|$Role"
    }
    $stream = New-Object IO.FileStream(
        $absolute,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None,
        4096,
        [IO.FileOptions]::WriteThrough)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    $readback = Read-AuthoritySignerLockedFile $absolute $Bytes.Length $Bytes.Length $Role
    if ($readback.sha256 -cne (Get-AuthoritySignerSha256 $Bytes)) {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_OUTPUT_READBACK_MISMATCH|$Role"
    }
    return $readback
}

function Write-AuthoritySignerAtomicReceipt([string]$Path, [byte[]]$Bytes, [object]$Anchor) {
    $absolute = Assert-AuthoritySignerNoReparseChain $Path $false 'receipt-target'
    $leaf = [IO.Path]::GetFileName($absolute)
    if ($leaf -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$') {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_RECEIPT_LEAF_INVALID'
    }
    $parent = [IO.Path]::GetDirectoryName($absolute)
    if (-not [IO.Path]::GetFullPath($parent).Equals(
            [IO.Path]::GetFullPath([string]$Anchor.path),
            [StringComparison]::OrdinalIgnoreCase)) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_RECEIPT_ANCHOR_MISMATCH'
    }
    Assert-AuthoritySignerStableDirectoryChain $Anchor 'receipt-pre-create'
    if ([IO.File]::Exists($absolute) -or [IO.Directory]::Exists($absolute)) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_RECEIPT_ALREADY_EXISTS'
    }
    $temporaryLeaf = '.mcace-production-authority-receipt-' +
        [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $writtenIdentity = [MCAceProductionAuthoritySignerFileIdentityV1]::WriteAtomicRelative(
            $Anchor.root_handle, $temporaryLeaf, $leaf, $Bytes)
    } catch {
        Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_RECEIPT_HANDLE_RELATIVE_INSTALL_FAILED|$($_.Exception.Message)"
    }
    Assert-AuthoritySignerStableDirectoryChain $Anchor 'receipt-post-create'
    $final = Read-AuthoritySignerLockedFile $absolute $Bytes.Length $Bytes.Length 'receipt-final'
    if ($final.sha256 -cne (Get-AuthoritySignerSha256 $Bytes) -or
            $final.identity -cne $writtenIdentity) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_RECEIPT_ATOMIC_INSTALL_MISMATCH'
    }
    return $final
}

function New-AuthoritySignerScratch([string]$PrivateParent) {
    $parent = Assert-AuthoritySignerNoReparseChain $PrivateParent $true 'private-parent'
    for ($attempt = 0; $attempt -lt 8; $attempt++) {
        $candidate = Join-Path $parent (
            '.mcace-production-authority-sign-' + [guid]::NewGuid().ToString('N'))
        if (-not [IO.Directory]::Exists($candidate) -and -not [IO.File]::Exists($candidate)) {
            [IO.Directory]::CreateDirectory($candidate) | Out-Null
            $null = Assert-AuthoritySignerNoReparseChain $candidate $true 'crypto-scratch'
            return $candidate
        }
    }
    Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_SCRATCH_CREATE_FAILED'
}

function Remove-AuthoritySignerScratch([string]$Path, [string]$PrivateParent) {
    $full = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetFullPath($PrivateParent)
    if (-not (Test-AuthoritySignerPathUnderRoot $full $parent) -or
            $full.Equals($parent, [StringComparison]::OrdinalIgnoreCase)) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_SCRATCH_DELETE_PATH_REJECTED'
    }
    if ([IO.Directory]::Exists($full)) {
        $null = Assert-AuthoritySignerNoReparseChain $full $true 'crypto-scratch-cleanup'
        foreach ($entry in @(Get-ChildItem -LiteralPath $full -Force)) {
            if ($entry.PSIsContainer -or
                    ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_SCRATCH_ENTRY_REJECTED'
            }
            [IO.File]::Delete($entry.FullName)
        }
        [IO.Directory]::Delete($full, $false)
    }
}

function Open-AuthoritySignerReplayLedger([string]$Path) {
    $absolute = Assert-AuthoritySignerNoReparseChain $Path $false 'replay-ledger'
    $parent = [IO.Path]::GetDirectoryName($absolute)
    $null = Assert-AuthoritySignerNoReparseChain $parent $true 'replay-ledger-parent'
    $existed = [IO.File]::Exists($absolute)
    $before = if ($existed) { Get-AuthoritySignerNoFollowIdentity $absolute } else { $null }
    try {
        $stream = New-Object IO.FileStream(
            $absolute,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough)
    } catch {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_REPLAY_LEDGER_OPEN_FAILED'
    }
    try {
        $handleIdentity = [MCAceProductionAuthoritySignerFileIdentityV1]::FromHandle(
            $stream.SafeFileHandle)
        if ($existed -and $handleIdentity -cne $before) {
            Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_REPLAY_LEDGER_IDENTITY_CHANGED'
        }
        $null = Assert-AuthoritySignerNoReparseChain $absolute $true 'replay-ledger'
        if ($stream.Length -gt 16777216) {
            Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_REPLAY_LEDGER_SIZE_INVALID'
        }
        return $stream
    } catch {
        $stream.Dispose()
        throw
    }
}

function Invoke-AuthoritySignerReplayProtectedReceipt(
        [string]$LedgerPath, [string]$OperationReplayId, [string]$ChallengeReplayId,
        [string]$RequestSha256, [string]$ReceiptPath, [byte[]]$ReceiptBytes,
        [object]$ExchangeAnchor) {
    Assert-AuthoritySignerSha256 $OperationReplayId 'operation_replay_id'
    Assert-AuthoritySignerSha256 $ChallengeReplayId 'challenge_replay_id'
    $stream = Open-AuthoritySignerReplayLedger $LedgerPath
    try {
        $length = [long]$stream.Length
        [byte[]]$ledgerBytes = if ($length -eq 0) {
            New-Object byte[] 0
        } else {
            $stream.Position = 0
            Read-AuthoritySignerExact $stream ([int]$length) 'replay-ledger'
        }
        try { $raw = $script:SignerUtf8Strict.GetString($ledgerBytes) }
        catch { Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_REPLAY_LEDGER_UTF8_INVALID' }
        if ($raw.Contains("`r") -or ($raw.Length -gt 0 -and -not $raw.EndsWith("`n"))) {
            Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_REPLAY_LEDGER_FORMAT_INVALID'
        }
        foreach ($line in @($raw -split "`n" | Where-Object { $_ -ne '' })) {
            if ($line -cnotmatch '^[0-9a-f]{64}\t[0-9a-f]{64}\t\d{4}-\d{2}-\d{2}T[^\t]+Z\t[0-9a-f]{64}\t[0-9a-f]{64}\t[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$') {
                Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_REPLAY_LEDGER_FORMAT_INVALID'
            }
            $columns = @($line.Split("`t"))
            if ($columns[0] -ceq $OperationReplayId) {
                Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_REPLAY_REJECTED|operation_attempt_id'
            }
            if ($columns[1] -ceq $ChallengeReplayId) {
                Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_REPLAY_REJECTED|challenge_nonce'
            }
        }
        $receiptHash = Get-AuthoritySignerSha256 $ReceiptBytes
        $record = "$OperationReplayId`t$ChallengeReplayId" +
            "`t$([DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))" +
            "`t$RequestSha256`t$receiptHash`t$([IO.Path]::GetFileName($ReceiptPath))`n"
        [byte[]]$recordBytes = $script:SignerUtf8NoBom.GetBytes($record)
        $stream.Position = $stream.Length
        $stream.Write($recordBytes, 0, $recordBytes.Length)
        $stream.Flush($true)
        return Write-AuthoritySignerAtomicReceipt $ReceiptPath $ReceiptBytes $ExchangeAnchor
    } finally { $stream.Dispose() }
}

if (-not $script:SignerIsWindows) {
    Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_WINDOWS_REQUIRED'
}

$expectedRequestPins = @($ExpectedRequestSha256, $ApprovedRequestSha256 |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    ForEach-Object { $_.ToLowerInvariant() } |
    Sort-Object -Unique)
if ($expectedRequestPins.Count -ne 1) {
    Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_SINGLE_APPROVED_REQUEST_SHA256_REQUIRED'
}
$approvedRequestPin = [string]$expectedRequestPins[0]
$ExpectedDescriptorSha256 = $ExpectedDescriptorSha256.ToLowerInvariant()
$ExpectedSignerKeyIdSha256 = $ExpectedSignerKeyIdSha256.ToLowerInvariant()
$ExpectedOpenSslSha256 = $ExpectedOpenSslSha256.ToLowerInvariant()
$ExpectedOpenSslRuntimeManifestSha256 = $ExpectedOpenSslRuntimeManifestSha256.ToLowerInvariant()

$allowedRoot = Assert-AuthoritySignerNoReparseChain $AllowedExchangeRoot $true 'allowed-exchange-root'
if (-not [IO.Directory]::Exists($allowedRoot) -or [IO.File]::Exists($allowedRoot)) {
    Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_EXCHANGE_ROOT_DIRECTORY_REQUIRED'
}
if (([IO.Path]::GetFullPath($allowedRoot)).TrimEnd('\','/').Equals(
        ([IO.Path]::GetPathRoot($allowedRoot)).TrimEnd('\','/'),
        [StringComparison]::OrdinalIgnoreCase) -or
        (Test-AuthoritySignerPathUnderRoot $allowedRoot $script:SignerRepoRoot)) {
    Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_EXCHANGE_ROOT_REJECTED'
}

$requestAbsolute = Assert-AuthoritySignerNoReparseChain $RequestPath $true 'request'
$receiptAbsolute = Assert-AuthoritySignerNoReparseChain $ReceiptPath $false 'receipt'
$descriptorAbsolute = Assert-AuthoritySignerNoReparseChain $ExpectedDescriptorPath $true 'descriptor'
$privateAbsolute = Assert-AuthoritySignerNoReparseChain $PrivateKeyPath $true 'private-key'
$openSslAbsolute = Assert-AuthoritySignerNoReparseChain $OpenSslPath $true 'openssl'
$runtimeManifestAbsolute = Assert-AuthoritySignerNoReparseChain `
    $OpenSslRuntimeManifestPath $true 'openssl-runtime-manifest'
foreach ($exchangePath in @($requestAbsolute, $receiptAbsolute)) {
    if (-not (Test-AuthoritySignerPathUnderRoot $exchangePath $allowedRoot) -or
            $exchangePath.Equals($allowedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_EXCHANGE_PATH_OUTSIDE_ALLOWLIST'
    }
}
$receiptParent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($receiptAbsolute)).TrimEnd('\','/')
$requestParent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($requestAbsolute)).TrimEnd('\','/')
$normalizedAllowedRoot = [IO.Path]::GetFullPath($allowedRoot).TrimEnd('\','/')
if (-not $receiptParent.Equals($normalizedAllowedRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not $requestParent.Equals($normalizedAllowedRoot, [StringComparison]::OrdinalIgnoreCase)) {
    Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_EXCHANGE_DIRECT_LEAVES_REQUIRED'
}
foreach ($trustedPath in @(
        $descriptorAbsolute, $privateAbsolute, $openSslAbsolute, $runtimeManifestAbsolute)) {
    if (Test-AuthoritySignerPathUnderRoot $trustedPath $allowedRoot) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_TRUSTED_INPUT_INSIDE_EXCHANGE_REJECTED'
    }
}
if ($requestAbsolute.Equals($receiptAbsolute, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.File]::Exists($receiptAbsolute) -or [IO.Directory]::Exists($receiptAbsolute)) {
    Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_RECEIPT_PATH_INVALID'
}
if ([IO.Path]::GetExtension($openSslAbsolute) -cne '.exe') {
    Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_APPLICATION_REQUIRED'
}

$privateParent = Assert-AuthoritySignerPrivateDirectoryAcl `
    ([IO.Path]::GetDirectoryName($privateAbsolute)) 'private-key-parent'
$ledgerPath = Join-Path $privateParent '.mcace-production-authority-v4-replay-v2.tsv'
$ledgerPath = Assert-AuthoritySignerNoReparseChain $ledgerPath $false 'replay-ledger'
if (Test-AuthoritySignerPathUnderRoot $ledgerPath $allowedRoot) {
    Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_REPLAY_LEDGER_INSIDE_EXCHANGE_REJECTED'
}

$mutexMaterial = $script:SignerUtf8NoBom.GetBytes(
    ([IO.Path]::GetFullPath($ledgerPath)).ToLowerInvariant())
$mutexName = 'Local\MCAceProductionAuthoritySignerV1-' +
    (Get-AuthoritySignerSha256 $mutexMaterial)
$mutex = New-Object Threading.Mutex($false, $mutexName)
$ownsMutex = $false
$exchangeAnchor = $null
$runtimeLocks = $null
try {
    $exchangeAnchor = Open-AuthoritySignerStableDirectoryChain $allowedRoot
    Assert-AuthoritySignerStableDirectoryChain $exchangeAnchor 'signer-start'
    try { $ownsMutex = $mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $ownsMutex = $true }
    if (-not $ownsMutex) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_CONCURRENT_OPERATION_REJECTED'
    }

    $requestDocument = Read-AuthoritySignerLockedFile $requestAbsolute 2 2097152 'request'
    if ($requestDocument.sha256 -cne $approvedRequestPin) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_REQUEST_NOT_IN_OPERATOR_ALLOWLIST'
    }
    $requestJson = ConvertFrom-AuthoritySignerJsonDocument $requestDocument 'request'
    $request = $requestJson.value
    $requestNames = @(
        'schema','artifact_class','request_id','issued_at','not_after','output_receipt_path',
        'capture_supervisor_descriptor_sha256','signer_key_id_sha256','source_commit',
        'artifact_source_commit','product_version','capture_id','operation_attempt_id',
        'challenge_nonce_base64','challenge_sha256','signed_payload_base64',
        'signed_payload_sha256','signed_payload_size_bytes','release_bundle_source_commit',
        'release_bundle_artifact_source_commit','paper_jar_sha256','paper_jar_size_bytes',
        'velocity_jar_sha256','velocity_jar_size_bytes','bungeecord_jar_sha256',
        'bungeecord_jar_size_bytes','raw_capture_manifest_sha256',
        'raw_capture_manifest_size_bytes','raw_evidence_root_sha256','raw_frame_set_sha256',
        'provider_evidence_commitment_sha256','profile_sha256','topology_sha256',
        'process_ledger_sha256','process_ledger_size_bytes','issuance_journal_sha256',
        'issuance_journal_size_bytes','test_fixture')
    if (-not (Test-AuthoritySignerExactProperties $request $requestNames)) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_REQUEST_PROPERTIES_INVALID'
    }
    $requestStringFields = @(
        'schema','artifact_class','request_id','issued_at','not_after','output_receipt_path',
        'capture_supervisor_descriptor_sha256','signer_key_id_sha256','source_commit',
        'artifact_source_commit','product_version','capture_id','operation_attempt_id',
        'challenge_nonce_base64','challenge_sha256','signed_payload_base64','signed_payload_sha256',
        'release_bundle_source_commit','release_bundle_artifact_source_commit','paper_jar_sha256',
        'velocity_jar_sha256','bungeecord_jar_sha256','raw_capture_manifest_sha256',
        'raw_evidence_root_sha256','raw_frame_set_sha256','provider_evidence_commitment_sha256',
        'profile_sha256','topology_sha256','process_ledger_sha256','issuance_journal_sha256')
    foreach ($field in $requestStringFields) { Assert-AuthoritySignerString $request.$field $field }
    foreach ($field in @('signed_payload_size_bytes','paper_jar_size_bytes',
            'velocity_jar_size_bytes','bungeecord_jar_size_bytes','raw_capture_manifest_size_bytes',
            'process_ledger_size_bytes','issuance_journal_size_bytes')) {
        if (-not (Test-AuthoritySignerJsonInteger $request.$field)) {
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_INTEGER_TYPE_INVALID|$field"
        }
    }
    if ($request.test_fixture -isnot [bool]) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_REQUEST_BOOLEAN_TYPE_INVALID'
    }
    if ($TestFixture) {
        if (-not [bool]$request.test_fixture -or
                $request.artifact_class -cne 'TEST_PRODUCTION_AUTHORITY_SIGNING_REQUEST_FIXTURE') {
            Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_TEST_REQUEST_REQUIRED'
        }
    } elseif ([bool]$request.test_fixture -or
            $request.artifact_class -cne 'EXTERNAL_PRODUCTION_AUTHORITY_RECEIPT_SIGNING_REQUEST') {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_FIXTURE_OR_NONPRODUCTION_REQUEST_REJECTED'
    }
    if ($request.schema -cne 'MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_SIGNING_REQUEST_V1') {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_REQUEST_SCHEMA_INVALID'
    }
    if (-not [IO.Path]::IsPathRooted([string]$request.output_receipt_path)) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OUTPUT_PATH_ABSOLUTE_REQUIRED'
    }
    $requestOutputAbsolute = [IO.Path]::GetFullPath([string]$request.output_receipt_path)
    if ([string]$request.output_receipt_path -cne $requestOutputAbsolute -or
            $requestOutputAbsolute -cne $receiptAbsolute) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OUTPUT_PATH_BINDING_INVALID'
    }
    Assert-AuthoritySignerGuid $request.request_id 'request_id'
    Assert-AuthoritySignerGuid $request.capture_id 'capture_id'
    Assert-AuthoritySignerGuid $request.operation_attempt_id 'operation_attempt_id'
    if ($request.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
            $request.artifact_source_commit -cnotmatch '^[0-9a-f]{40}$' -or
            $request.release_bundle_source_commit -cne $request.source_commit -or
            $request.release_bundle_artifact_source_commit -cne $request.artifact_source_commit -or
            $request.product_version -cne '0.0.1') {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_RELEASE_IDENTITY_INVALID'
    }

    $descriptorDocument = Read-AuthoritySignerLockedFile $descriptorAbsolute 2 65536 'descriptor'
    if ($descriptorDocument.sha256 -cne $ExpectedDescriptorSha256) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_DESCRIPTOR_SHA256_MISMATCH'
    }
    $descriptorJson = ConvertFrom-AuthoritySignerJsonDocument $descriptorDocument 'descriptor'
    $descriptor = $descriptorJson.value
    if (-not (Test-AuthoritySignerExactProperties $descriptor @(
            'schema','artifact_class','algorithm','key_id_sha256','public_key_der_base64',
            'test_fixture')) -or
            $descriptor.schema -cne 'MCACE_PRODUCTION_AUTHORITY_CAPTURE_SUPERVISOR_PUBLIC_DESCRIPTOR_V1' -or
            $descriptor.artifact_class -cne 'EXTERNAL_RELEASE_CAPTURE_SUPERVISOR_PUBLIC_ROOT' -or
            $descriptor.algorithm -cne 'ED25519' -or
            $descriptor.key_id_sha256 -isnot [string] -or
            $descriptor.public_key_der_base64 -isnot [string] -or
            $descriptor.test_fixture -isnot [bool] -or [bool]$descriptor.test_fixture) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_DESCRIPTOR_SCHEMA_INVALID'
    }
    Assert-AuthoritySignerSha256 $descriptor.key_id_sha256 'descriptor_key_id_sha256'
    [byte[]]$publicDer = ConvertFrom-AuthoritySignerBase64 `
        $descriptor.public_key_der_base64 32 256 'descriptor_public_key_der_base64'
    if ((Get-AuthoritySignerSha256 $publicDer) -cne [string]$descriptor.key_id_sha256 -or
            [string]$descriptor.key_id_sha256 -cne $ExpectedSignerKeyIdSha256 -or
            [string]$request.capture_supervisor_descriptor_sha256 -cne $ExpectedDescriptorSha256 -or
            [string]$request.signer_key_id_sha256 -cne $ExpectedSignerKeyIdSha256) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_DESCRIPTOR_BINDING_INVALID'
    }

    $runtime = Resolve-AuthoritySignerOpenSslRuntime `
        $runtimeManifestAbsolute $ExpectedOpenSslRuntimeManifestSha256 `
        $openSslAbsolute $ExpectedOpenSslSha256
    $runtimeLocks = Open-AuthoritySignerRuntimeLocks $runtime
    $openSslEntry = $runtime.entries[$runtime.executable_relative_path]
    $tool = [pscustomobject]@{
        path=$runtime.executable_path
        sha256=$openSslEntry.sha256
        identity=$openSslEntry.identity
        runtime=$runtime
        runtime_locks=$runtimeLocks
    }
    $version = Invoke-AuthoritySignerOpenSsl $tool @('version') 'version'
    if (($version -join "`n") -cnotmatch '(?m)^OpenSSL\s+3(?:\.|\s)') {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_3_REQUIRED'
    }
    $privateDocument = Read-AuthoritySignerLockedFile $privateAbsolute 32 4096 'private-key'

    [byte[]]$challenge = ConvertFrom-AuthoritySignerBase64 `
        $request.challenge_nonce_base64 32 32 'challenge_nonce_base64'
    if ((Get-AuthoritySignerSha256 $challenge) -cne [string]$request.challenge_sha256) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_CHALLENGE_HASH_MISMATCH'
    }
    [byte[]]$payloadBytes = ConvertFrom-AuthoritySignerBase64 `
        $request.signed_payload_base64 256 65536 'signed_payload_base64'
    if ((Get-AuthoritySignerSha256 $payloadBytes) -cne [string]$request.signed_payload_sha256 -or
            [long]$request.signed_payload_size_bytes -ne $payloadBytes.Length) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_PAYLOAD_BINDING_INVALID'
    }
    $payloadDocument = [pscustomobject]@{
        bytes=$payloadBytes
        sha256=(Get-AuthoritySignerSha256 $payloadBytes)
        size_bytes=[long]$payloadBytes.Length
        identity='embedded-request-payload'
    }
    $payloadJson = ConvertFrom-AuthoritySignerJsonDocument $payloadDocument 'payload'
    $payload = $payloadJson.value
    if ($payloadJson.raw.Contains("`r") -or $payloadJson.raw.EndsWith("`n")) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_PAYLOAD_CANONICAL_JSON_INVALID'
    }
    [byte[]]$roundTripPayload = $script:SignerUtf8NoBom.GetBytes(
        ($payload | ConvertTo-Json -Depth 30 -Compress))
    if (-not (Test-AuthoritySignerBytesEqual $payloadBytes $roundTripPayload)) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_PAYLOAD_CANONICAL_JSON_INVALID'
    }
    $payloadNames = @(
        'schema','artifact_class','source_commit','artifact_source_commit','product_version',
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
    if (-not (Test-AuthoritySignerExactProperties $payload $payloadNames)) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_PAYLOAD_PROPERTIES_INVALID'
    }
    $payloadStringFields = @(
        'schema','artifact_class','source_commit','artifact_source_commit','product_version',
        'capture_id','operation_attempt_id','supervisor_instance_id','supervisor_run_id',
        'signer_key_id_sha256','challenge_nonce_base64','issued_at','expires_at',
        'raw_capture_manifest_sha256','raw_evidence_root_sha256','raw_frame_set_sha256',
        'provider_evidence_commitment_sha256','event_chain_root_sha256','process_ledger_sha256',
        'paper_jar_sha256','velocity_jar_sha256','bungeecord_jar_sha256','selected_proxy',
        'selected_proxy_jar_sha256','profile_sha256','topology_sha256','backend_key_id_sha256',
        'proxy_key_id_sha256','action_ceiling','licensed_vulcan_sha256')
    foreach ($field in $payloadStringFields) {
        Assert-AuthoritySignerString $payload.$field "payload_$field"
    }
    foreach ($field in @('raw_capture_manifest_size_bytes','raw_frame_count','event_count',
            'process_ledger_size_bytes','paper_jar_size_bytes','velocity_jar_size_bytes',
            'bungeecord_jar_size_bytes','automatic_action_count')) {
        if (-not (Test-AuthoritySignerJsonInteger $payload.$field)) {
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_PAYLOAD_INTEGER_TYPE_INVALID|$field"
        }
    }
    if ($payload.cleanup_all_zero -isnot [bool] -or $payload.test_fixture -isnot [bool] -or
            $payload.genuine_provider_ids -isnot [Array]) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_PAYLOAD_COMPLEX_TYPE_INVALID'
    }
    foreach ($provider in @($payload.genuine_provider_ids)) {
        if ($provider -isnot [string]) {
            Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_PROVIDER_ID_TYPE_INVALID'
        }
    }
    if ($payload.schema -cne 'MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_PAYLOAD_V1') {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_PAYLOAD_SCHEMA_INVALID'
    }
    if ($TestFixture) {
        if (-not [bool]$payload.test_fixture -or
                $payload.artifact_class -cne 'TEST_SUPERVISOR_RECEIPT_FIXTURE') {
            Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_TEST_PAYLOAD_REQUIRED'
        }
    } elseif ([bool]$payload.test_fixture -or
            $payload.artifact_class -cne 'EXTERNAL_SUPERVISOR_SIGNED_PRODUCTION_CAPTURE') {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_FIXTURE_OR_NONPRODUCTION_PAYLOAD_REJECTED'
    }
    Assert-AuthoritySignerGuid $payload.capture_id 'payload_capture_id'
    Assert-AuthoritySignerGuid $payload.operation_attempt_id 'payload_operation_attempt_id'
    Assert-AuthoritySignerGuid $payload.supervisor_run_id 'payload_supervisor_run_id'
    if ([string]::IsNullOrWhiteSpace([string]$payload.supervisor_instance_id) -or
            ([string]$payload.supervisor_instance_id).Length -gt 128 -or
            [string]$payload.supervisor_instance_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._@/+~-]*$') {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_SUPERVISOR_INSTANCE_ID_INVALID'
    }

    $issued = ConvertFrom-AuthoritySignerUtc $request.issued_at 'issued_at'
    $notAfter = ConvertFrom-AuthoritySignerUtc $request.not_after 'not_after'
    $payloadIssued = ConvertFrom-AuthoritySignerUtc $payload.issued_at 'payload_issued_at'
    $payloadExpires = ConvertFrom-AuthoritySignerUtc $payload.expires_at 'payload_expires_at'
    $now = [DateTimeOffset]::UtcNow
    if ($payloadIssued.UtcDateTime.Ticks -ne $issued.UtcDateTime.Ticks -or
            $payloadExpires.UtcDateTime.Ticks -ne $notAfter.UtcDateTime.Ticks -or
            $notAfter -le $issued -or ($notAfter - $issued).TotalSeconds -gt 900 -or
            $now -lt $issued.AddSeconds(-5) -or $now -ge $notAfter) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_REQUEST_EXPIRED_OR_TIME_INVALID'
    }

    foreach ($field in @(
            'challenge_sha256','signed_payload_sha256','capture_supervisor_descriptor_sha256',
            'signer_key_id_sha256','paper_jar_sha256','velocity_jar_sha256',
            'bungeecord_jar_sha256','raw_capture_manifest_sha256','raw_evidence_root_sha256',
            'raw_frame_set_sha256','provider_evidence_commitment_sha256','profile_sha256',
            'topology_sha256','process_ledger_sha256','issuance_journal_sha256')) {
        Assert-AuthoritySignerSha256 $request.$field $field
    }
    foreach ($field in @(
            'signer_key_id_sha256','raw_capture_manifest_sha256','raw_evidence_root_sha256',
            'raw_frame_set_sha256','provider_evidence_commitment_sha256','event_chain_root_sha256',
            'process_ledger_sha256','paper_jar_sha256','velocity_jar_sha256',
            'bungeecord_jar_sha256','selected_proxy_jar_sha256','profile_sha256','topology_sha256',
            'backend_key_id_sha256','proxy_key_id_sha256','licensed_vulcan_sha256')) {
        Assert-AuthoritySignerSha256 $payload.$field "payload_$field"
    }
    foreach ($field in @('signed_payload_size_bytes','paper_jar_size_bytes',
            'velocity_jar_size_bytes','bungeecord_jar_size_bytes','raw_capture_manifest_size_bytes',
            'process_ledger_size_bytes','issuance_journal_size_bytes')) {
        if ([long]$request.$field -le 0 -or [long]$request.$field -gt 1099511627776) {
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_INTEGER_INVALID|$field"
        }
    }
    foreach ($field in @('raw_capture_manifest_size_bytes','process_ledger_size_bytes',
            'paper_jar_size_bytes','velocity_jar_size_bytes','bungeecord_jar_size_bytes')) {
        if ([long]$payload.$field -le 0 -or [long]$payload.$field -gt 1099511627776) {
            Throw-AuthoritySigner "PRODUCTION_AUTHORITY_SIGNER_PAYLOAD_INTEGER_INVALID|$field"
        }
    }
    if ([long]$payload.event_count -le 0 -or [long]$payload.event_count -gt 1000000 -or
            [long]$payload.raw_frame_count -ne 2 -or
            [long]$payload.automatic_action_count -ne 0 -or
            -not [bool]$payload.cleanup_all_zero -or
            $payload.action_ceiling -cne 'MONITOR' -or
            $payload.selected_proxy -cnotin @('velocity','bungeecord') -or
            @($payload.genuine_provider_ids).Count -ne 2 -or
            [string]$payload.genuine_provider_ids[0] -cne 'grim' -or
            [string]$payload.genuine_provider_ids[1] -cne 'vulcan' -or
            @($payload.genuine_provider_ids | Sort-Object -Unique).Count -ne 2) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_PRODUCTION_POLICY_INVALID'
    }
    if ($payload.source_commit -cne $request.source_commit -or
            $payload.artifact_source_commit -cne $request.artifact_source_commit -or
            $payload.product_version -cne $request.product_version -or
            $payload.capture_id -cne $request.capture_id -or
            $payload.operation_attempt_id -cne $request.operation_attempt_id -or
            $payload.signer_key_id_sha256 -cne $request.signer_key_id_sha256 -or
            $payload.challenge_nonce_base64 -cne $request.challenge_nonce_base64) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_PAYLOAD_IDENTITY_MISMATCH'
    }
    $selectedRequestHash = if ($payload.selected_proxy -ceq 'velocity') {
        [string]$request.velocity_jar_sha256
    } else { [string]$request.bungeecord_jar_sha256 }
    if ($payload.selected_proxy_jar_sha256 -cne $selectedRequestHash) {
        Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_SELECTED_PROXY_BINDING_INVALID'
    }
    $crossBindings = [ordered]@{
        paper_jar_sha256='paper_jar_sha256'
        paper_jar_size_bytes='paper_jar_size_bytes'
        velocity_jar_sha256='velocity_jar_sha256'
        velocity_jar_size_bytes='velocity_jar_size_bytes'
        bungeecord_jar_sha256='bungeecord_jar_sha256'
        bungeecord_jar_size_bytes='bungeecord_jar_size_bytes'
        raw_capture_manifest_sha256='raw_capture_manifest_sha256'
        raw_capture_manifest_size_bytes='raw_capture_manifest_size_bytes'
        raw_evidence_root_sha256='raw_evidence_root_sha256'
        raw_frame_set_sha256='raw_frame_set_sha256'
        provider_evidence_commitment_sha256='provider_evidence_commitment_sha256'
        profile_sha256='profile_sha256'
        topology_sha256='topology_sha256'
        process_ledger_sha256='process_ledger_sha256'
        process_ledger_size_bytes='process_ledger_size_bytes'
    }
    foreach ($entry in $crossBindings.GetEnumerator()) {
        if ([string]$payload.([string]$entry.Key) -cne
                [string]$request.([string]$entry.Value)) {
            Throw-AuthoritySigner (
                "PRODUCTION_AUTHORITY_SIGNER_PAYLOAD_CROSS_BINDING_INVALID|$($entry.Key)")
        }
    }

    $scratch = New-AuthoritySignerScratch $privateParent
    $derivedPublicPath = Join-Path $scratch 'derived-public.der'
    $descriptorPublicPath = Join-Path $scratch 'descriptor-public.der'
    $payloadPath = Join-Path $scratch 'payload.bin'
    $signaturePath = Join-Path $scratch 'signature.bin'
    try {
        $null = Write-AuthoritySignerCreateNewFile $descriptorPublicPath $publicDer 'descriptor-public'
        $null = Write-AuthoritySignerCreateNewFile $payloadPath $payloadBytes 'payload'
        $null = Invoke-AuthoritySignerOpenSsl $tool @(
            'pkey','-inform','DER','-in',$privateAbsolute,
            '-pubout','-outform','DER','-out',$derivedPublicPath) 'derive-public'
        $derived = Read-AuthoritySignerLockedFile $derivedPublicPath 32 256 'derived-public'
        if (-not (Test-AuthoritySignerBytesEqual $derived.bytes $publicDer) -or
                $derived.sha256 -cne $ExpectedSignerKeyIdSha256) {
            Throw-AuthoritySigner 'PRODUCTION_AUTHORITY_SIGNER_PRIVATE_PUBLIC_MISMATCH'
        }
        $null = Invoke-AuthoritySignerOpenSsl $tool @(
            'pkeyutl','-sign','-rawin','-inkey',$privateAbsolute,'-keyform','DER',
            '-in',$payloadPath,'-out',$signaturePath) 'sign-payload'
        $signature = Read-AuthoritySignerLockedFile $signaturePath 64 64 'signature'
        $null = Invoke-AuthoritySignerOpenSsl $tool @(
            'pkeyutl','-verify','-rawin','-pubin','-inkey',$descriptorPublicPath,
            '-keyform','DER','-in',$payloadPath,'-sigfile',$signaturePath) 'verify-signature'
        $receipt = [pscustomobject][ordered]@{
            schema='MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_V1'
            signed_payload_base64=[string]$request.signed_payload_base64
            signed_payload_sha256=[string]$request.signed_payload_sha256
            signature_base64=[Convert]::ToBase64String([byte[]]$signature.bytes)
        }
        [byte[]]$receiptBytes = $script:SignerUtf8NoBom.GetBytes(
            ($receipt | ConvertTo-Json -Depth 8 -Compress))
    } finally {
        Remove-AuthoritySignerScratch $scratch $privateParent
    }

    Assert-AuthoritySignerStableDocument $requestAbsolute $requestDocument 2 2097152 'request'
    Assert-AuthoritySignerStableDocument $descriptorAbsolute $descriptorDocument 2 65536 'descriptor'
    Assert-AuthoritySignerStableDocument $privateAbsolute $privateDocument 32 4096 'private-key'
    Assert-AuthoritySignerRuntimeLocked $runtime $runtimeLocks 'before-receipt-publication'
    Assert-AuthoritySignerStableDirectoryChain $exchangeAnchor 'before-receipt-publication'

    $operationReplayMaterial = "MCACE_PRODUCTION_AUTHORITY_V4_OPERATION_REPLAY_V2`n" +
        "signer_key_id_sha256=$ExpectedSignerKeyIdSha256`n" +
        "operation_attempt_id=$($request.operation_attempt_id)`n"
    $challengeReplayMaterial = "MCACE_PRODUCTION_AUTHORITY_V4_CHALLENGE_REPLAY_V2`n" +
        "signer_key_id_sha256=$ExpectedSignerKeyIdSha256`n" +
        "challenge_nonce_base64=$($request.challenge_nonce_base64)`n"
    $operationReplayId = Get-AuthoritySignerSha256 `
        $script:SignerUtf8NoBom.GetBytes($operationReplayMaterial)
    $challengeReplayId = Get-AuthoritySignerSha256 `
        $script:SignerUtf8NoBom.GetBytes($challengeReplayMaterial)
    $output = Invoke-AuthoritySignerReplayProtectedReceipt `
        $ledgerPath $operationReplayId $challengeReplayId $requestDocument.sha256 `
        $receiptAbsolute $receiptBytes $exchangeAnchor
    $kind = if ($TestFixture) { 'FIXTURE' } else { 'PRODUCTION' }
    Write-Output ("PRODUCTION_AUTHORITY_V4_SIGNER_{0}_CREATED|sha256={1}|output={2}" -f
        $kind,$output.sha256,$output.path)
} finally {
    try {
        Close-AuthoritySignerRuntimeLocks $runtimeLocks
    } finally {
        try {
            Close-AuthoritySignerStableDirectoryChain $exchangeAnchor
        } finally {
            try {
                if ($ownsMutex) { $mutex.ReleaseMutex() }
            } finally { $mutex.Dispose() }
        }
    }
}
