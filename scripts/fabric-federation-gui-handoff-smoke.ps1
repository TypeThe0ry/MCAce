[CmdletBinding(DefaultParameterSetName = 'Disabled')]
param(
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [switch]$Execute,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [switch]$ReportOnly,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidateSet('1.21.11', '26.1.2', '26.2')]
    [string]$FabricTarget,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidateSet('VELOCITY', 'BUNGEE')]
    [string]$SourceProxy,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidateSet('VELOCITY', 'BUNGEE')]
    [string]$TargetProxy,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [string]$VisibleGuiSigningRequestPath,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [string]$VisibleGuiAttestationPath,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [string]$VisibleGuiScreenshotPath,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [string]$VisibleGuiTrustRootPath,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedVisibleGuiTrustRootSha256,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [string]$PostRunSupervisorTrustRootPath,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPostRunSupervisorTrustRootSha256,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [string]$PostRunSigningRequestPath,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [string]$PostRunReceiptPath,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [string]$ReleaseBundleRoot,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedFabricArtifactSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedVelocityPluginSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedBungeePluginSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPaperPluginSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedVelocityServerSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedBungeeServerSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPaperServerSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPaperPreparedManifestSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPaperPreparedTreeSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedFabricVersionInfoSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedFabricAssetIndexSha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedFabricAssetObjectManifestSha256,
    [Parameter(ParameterSetName = 'Execute')]
    [ValidateRange(60, 300)]
    [int]$FederationAssertionTtlSeconds = 120,
    [Parameter(ParameterSetName = 'Execute')]
    [ValidateRange(30, 180)]
    [int]$HumanTransitionTimeoutSeconds = 180,
    [Parameter(ParameterSetName = 'Execute')]
    [ValidateRange(30, 300)]
    [int]$PostRunReceiptTimeoutSeconds = 120,
    [ValidateRange(1, 1440)]
    [int]$MaximumReportAgeMinutes = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $Execute -and -not $ReportOnly) {
    throw 'FABRIC_FEDERATION_GUI_EXPLICIT_EXECUTE_OR_REPORT_ONLY_REQUIRED'
}
$SourceProxy = $SourceProxy.ToUpperInvariant()
$TargetProxy = $TargetProxy.ToUpperInvariant()

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$wrapperPath = [System.IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$wrapperTestPath = Join-Path $PSScriptRoot 'test-fabric-federation-gui-handoff-smoke.ps1'
$platformWrapperPath = Join-Path $PSScriptRoot 'platform-load-smoke.ps1'
$evidenceRoot = Join-Path $repoRoot 'build\fabric-federation-gui-handoff'
$evidenceRunsRoot = Join-Path $evidenceRoot 'evidence-runs'
$serverMatrixRoot = Join-Path $repoRoot 'build\runtime-assets'
$serverMatrixManifest = Join-Path $serverMatrixRoot 'manifest.json'
$serverPreparedManifest = Join-Path $serverMatrixRoot 'prepared-manifest.json'
$stagedModernDependencies = Join-Path $repoRoot 'build\fabric-modern-deps'
$releaseBundleRuntimeRoot = [System.IO.Path]::GetFullPath($ReleaseBundleRoot)
$velocityPlugin = Join-Path $releaseBundleRuntimeRoot 'mcace-server-velocity.jar'
$bungeePlugin = Join-Path $releaseBundleRuntimeRoot 'mcace-server-bungeecord.jar'
$paperPlugin = Join-Path $releaseBundleRuntimeRoot 'mcace-server-paper.jar'
$gradleVersion = '9.6.1'
$fabricArtifactVersion = '0.0.1'
$reportSchema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EXECUTED_V5'
$bindingSchema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_BINDING_V5'
$commitSchema = 'MCACE_FABRIC_FEDERATION_GUI_HANDOFF_COMMIT_V5'
$visibleGuiSigningRequestSchema = 'MCACE_VISIBLE_GUI_SIGNING_REQUEST_V1'
$visibleGuiSigningRequestDomain = 'MCACE_VISIBLE_GUI_SIGNING_REQUEST_CANONICAL_V1'
$visibleGuiAttestationSchema = 'MCACE_VISIBLE_GUI_ATTESTATION_V3'
$visibleGuiAttestationSigningDomain = 'MCACE_VISIBLE_GUI_ATTESTATION_SIGNING_V3'
$visibleGuiTrustRootSchema = 'MCACE_VISIBLE_GUI_TRUST_ROOT_V1'
$postRunReceiptSchema = 'MCACE_FABRIC_FEDERATION_POSTRUN_RECEIPT_V1'
$postRunTrustRootSchema = 'MCACE_FEDERATION_POSTRUN_TRUST_ROOT_V1'
$runtimeEventSchema = 'MCACE_FABRIC_FEDERATION_RUNTIME_EVENT_V1'
$visibleGuiAttestationArtifactClass = 'EXTERNAL_OPERATOR_VISIBLE_GUI_ATTESTATION'
$visibleGuiAttestationSourceMode = 'EXTERNAL_COMPUTER_USE_CAPTURE'
$visibleGuiSigningRequestArtifactClass = 'RUNNER_GENERATED_VISIBLE_GUI_SIGNING_REQUEST'
$visibleGuiSigningRequestSourceMode = 'LOCAL_NOFOLLOW_ATOMIC_EXCHANGE'
$postRunReceiptArtifactClass = 'EXTERNAL_FEDERATION_POSTRUN_SUPERVISOR_RECEIPT'
$artifactClass = 'sanitized-final-fabric-federation-gui-handoff-v5'
$requiredHumanGuiMarkers = @(
    'MCAce enablement consent requested for signed policy',
    'MCAce enablement consent screen rendered',
    'MCAce enablement accepted for the current connection; no additional consent screens will be shown',
    "MCAce reserved the connection's single federation source export permit",
    'MCAce federation target import consent inherited from connection enablement',
    'MCAce federation target connection enablement inherited from one-time source approval',
    'MCAce federation target authorization promoted to the current connection after one-time presentation commit'
)

# The platform gate is the single target/JDK/cache/artifact authority. Import its exact
# function ASTs and descriptor assignment instead of maintaining a weaker second copy.
$platformTokens = $null
$platformErrors = $null
$platformAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $platformWrapperPath, [ref]$platformTokens, [ref]$platformErrors)
if (@($platformErrors).Count -ne 0) {
    throw 'FABRIC_FEDERATION_GUI_PLATFORM_WRAPPER_PARSE_FAILED'
}
$platformFunctionNames = @(
    'Assert-SmokeRunToken', 'New-SmokeRunToken', 'Test-ExactRunTokenArgument',
    'Get-Sha256', 'Get-Sha1', 'Get-ObjectProperty', 'Resolve-ServerMatrixAssets',
    'Assert-FabricAssetCache', 'Assert-DirectLocalPath', 'Initialize-SafeOwnedDirectory',
    'New-ExclusiveOwnedDirectory', 'Assert-OwnedTreeNoReparse', 'Get-VerifiedArtifact',
    'Get-FreeLoopbackPort', 'Test-LoopbackPortFree', 'Assert-LoopbackListener',
    'Set-ProcessArguments', 'Test-TextContains', 'Get-Sha256HexFromBytes',
    'Get-CompatibleRelativePath', 'Resolve-ExactJava', 'Resolve-RootJava21',
    'Resolve-TargetJava', 'Resolve-OfflineGradle961', 'Invoke-PinnedOfflineGradle',
    'Expand-VelocityConfiguration', 'Test-JarEntry', 'Get-FabricArtifactIdentity',
    'Assert-FabricArtifactMarker', 'Get-SmokeProcessTreeTargets',
    'Stop-SmokeProcessTree', 'Get-RunTokenJavaProcesses', 'Stop-RunTokenJavaProcesses',
    'Stop-JavaService', 'Get-FabricDevelopmentPlayerName', 'Get-BytesSha256',
    'Get-ManifestSha256', 'Get-SourceManifestBinding', 'Assert-CanonicalPreparedRelative',
    'Get-PreparedTreeBinding', 'Get-PreparedPaperBinding', 'Get-JsonPropertyNames',
    'Test-ExactJsonProperties', 'Test-JsonInteger'
)
$platformFunctions = @($platformAst.FindAll({
    param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $true))
foreach ($functionName in $platformFunctionNames) {
    $matches = @($platformFunctions | Where-Object Name -CEQ $functionName)
    if ($matches.Count -ne 1) {
        throw "FABRIC_FEDERATION_GUI_PLATFORM_FUNCTION_CONTRACT_INVALID: $functionName"
    }
    Invoke-Expression $matches[0].Extent.Text
}
$targetAssignments = @($platformAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$fabricTargets'
}, $true))
if ($targetAssignments.Count -ne 1) {
    throw 'FABRIC_FEDERATION_GUI_PLATFORM_TARGET_DESCRIPTOR_CONTRACT_INVALID'
}
$fabricTargets = Invoke-Expression $targetAssignments[0].Right.Extent.Text
if (@($fabricTargets.Keys).Count -ne 3 -or
        ((@($fabricTargets.Keys) -join ',') -cne '1.21.11,26.1.2,26.2')) {
    throw 'FABRIC_FEDERATION_GUI_PLATFORM_TARGET_SET_INVALID'
}
$fabricDescriptor = $fabricTargets[$FabricTarget]
if ($null -eq $fabricDescriptor) {
    throw 'FABRIC_FEDERATION_GUI_FABRIC_TARGET_INVALID'
}
$fabricRuntimeMode = if ([int]$fabricDescriptor.java_major -eq 21) {
    'PRODUCTION_FINAL_REMAP_RELEASE_JAR'
} else { 'LOOM_FINAL_NAMED_RELEASE_JAR' }
$fabricArtifactJar = Join-Path $releaseBundleRuntimeRoot "mcace-client-fabric-$FabricTarget.jar"
$preparedPaperRoot = ''
$velocityArtifact = [ordered]@{
    Name = 'velocity-3.5.1-615.jar'
    Url = 'https://fill-data.papermc.io/v1/objects/b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3/velocity-3.5.1-615.jar'
    Sha256 = 'b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3'
}

function ConvertFrom-StrictJson([string]$Raw) {
    $trimmed = $Raw.Trim()
    if ($trimmed.Length -lt 2 -or $trimmed[0] -cne '{' -or
            $trimmed[$trimmed.Length - 1] -cne '}') {
        throw 'FABRIC_FEDERATION_GUI_JSON_TOP_LEVEL_OBJECT_REQUIRED'
    }
    $command = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
    if ($command.Parameters.ContainsKey('DateKind')) {
        $value = ConvertFrom-Json -InputObject $Raw -DateKind String -ErrorAction Stop
    } else {
        $value = ConvertFrom-Json -InputObject $Raw -ErrorAction Stop
    }
    # All V4 evidence documents are deliberately flat scalar objects. Count raw property tokens
    # against the converted top-level object and reject case-insensitive duplicates so PowerShell's
    # object adapter cannot collapse duplicate JSON names into an apparently valid schema.
    $propertyMatches = [regex]::Matches(
        $Raw, '"(?<name>[^"\r\n]+)"\s*:',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $properties = @($value.PSObject.Properties)
    if ($propertyMatches.Count -ne $properties.Count) {
        throw 'FABRIC_FEDERATION_GUI_JSON_FLAT_UNIQUE_PROPERTIES_REQUIRED'
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($match in $propertyMatches) {
        if (-not $seen.Add($match.Groups['name'].Value)) {
            throw 'FABRIC_FEDERATION_GUI_JSON_FLAT_UNIQUE_PROPERTIES_REQUIRED'
        }
    }
    return $value
}

function Assert-SanitizedJson([string]$Raw) {
    if ($Raw.Length -gt 65536 -or
            $Raw -match '(?i)[A-Z]:[\\/]|\\\\|(?:^|["\s])/(?!/)[^"\r\n]*' -or
            $Raw -match '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b' -or
            $Raw -match '(?i)private.?key|client.?secret|access.?token|raw.?grant|raw.?presentation') {
        throw 'FABRIC_FEDERATION_GUI_EVIDENCE_NOT_SANITIZED'
    }
}

function Open-LockedEvidence([string]$Path) {
    $resolved = Assert-DirectLocalPath $Path
    $identityBefore = Get-NoFollowFileIdentity $resolved
    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $resolved, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read)
        if ($stream.Length -le 0L -or $stream.Length -gt 65536L) {
            throw 'FABRIC_FEDERATION_GUI_EVIDENCE_SIZE_INVALID'
        }
        $memory = [System.IO.MemoryStream]::new()
        try { $stream.CopyTo($memory); $bytes = $memory.ToArray() }
        finally { $memory.Dispose() }
        $raw = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        Assert-SanitizedJson $raw
        Assert-LockedFileIdentity $resolved $stream $identityBefore
        return [pscustomobject]@{
            raw = $raw
            bytes = $bytes
            sha256 = Get-BytesSha256 $bytes
            size_bytes = [long]$bytes.Length
            file_identity = $identityBefore
            stream = $stream
        }
    } catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}

function Write-NewLockedJsonExchange([string]$Path, [string]$Content) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Content)
    if ($bytes.Length -le 0 -or $bytes.Length -gt 65536) {
        throw 'FABRIC_FEDERATION_GUI_SIGNING_REQUEST_SIZE_INVALID'
    }
    Assert-SanitizedJson $Content
    $stream = $null
    try {
        $stream = [IO.File]::Open(
            $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        if (Test-IsWindowsPlatform) {
            Initialize-WindowsFileIdentityApi
            try { $identity = [MCAceFederationFileIdentityV4]::FromHandle($stream.SafeFileHandle) }
            catch { throw "FABRIC_FEDERATION_GUI_HANDLE_IDENTITY_FAILED: $($_.Exception.Message)" }
        } else {
            $identity = Get-NoFollowFileIdentity $Path
        }
        if ((Get-NoFollowFileIdentity $Path) -cne $identity) {
            throw 'FABRIC_FEDERATION_GUI_SIGNING_REQUEST_IDENTITY_CHANGED_AFTER_CREATE'
        }
        $stream.Position = 0
        $memory = [IO.MemoryStream]::new()
        try { $stream.CopyTo($memory); $readback = $memory.ToArray() }
        finally { $memory.Dispose() }
        if ($readback.Length -ne $bytes.Length -or
                (Get-BytesSha256 $readback) -cne (Get-BytesSha256 $bytes)) {
            throw 'FABRIC_FEDERATION_GUI_SIGNING_REQUEST_ATOMIC_READBACK_MISMATCH'
        }
        $stream.Position = 0
        return [pscustomobject]@{
            raw = $Content
            bytes = $bytes
            sha256 = Get-BytesSha256 $bytes
            size_bytes = [long]$bytes.Length
            file_identity = $identity
            stream = $stream
        }
    } catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}

function Test-IsWindowsPlatform {
    if (Get-Variable IsWindows -ErrorAction SilentlyContinue) { return [bool]$IsWindows }
    return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

function Initialize-WindowsFileIdentityApi {
    if (-not (Test-IsWindowsPlatform) -or
            ('MCAceFederationFileIdentityV4' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class MCAceFederationFileIdentityV4 {
    private const uint FILE_READ_ATTRIBUTES = 0x80;
    private const uint FILE_SHARE_READ = 0x1;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION {
        public uint FileAttributes;
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

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION info);

    private static string Describe(BY_HANDLE_FILE_INFORMATION info) {
        return info.VolumeSerialNumber.ToString("x8") + ":" +
            info.FileIndexHigh.ToString("x8") + info.FileIndexLow.ToString("x8");
    }

    public static string NoFollow(string path, bool directory) {
        uint flags = FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0u);
        using (SafeFileHandle handle = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(handle, out info))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                throw new InvalidOperationException("reparse point rejected");
            return Describe(info);
        }
    }

    public static string FromHandle(SafeFileHandle handle) {
        BY_HANDLE_FILE_INFORMATION info;
        if (!GetFileInformationByHandle(handle, out info))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if ((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            throw new InvalidOperationException("reparse point rejected");
        return Describe(info);
    }
}
'@
}

function Get-NoFollowFileIdentity([string]$Path, [switch]$Directory) {
    if (-not (Test-IsWindowsPlatform)) {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($item.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $item.LinkType)) {
            throw 'FABRIC_FEDERATION_GUI_REPARSE_IDENTITY_REJECTED'
        }
        return "portable:$([string]$item.FullName):$([long]$item.Length):$($item.LastWriteTimeUtc.Ticks)"
    }
    Initialize-WindowsFileIdentityApi
    try { return [MCAceFederationFileIdentityV4]::NoFollow($Path, [bool]$Directory) }
    catch { throw "FABRIC_FEDERATION_GUI_NOFOLLOW_IDENTITY_FAILED: $($_.Exception.Message)" }
}

function Assert-LockedFileIdentity([string]$Path, [IO.FileStream]$Stream, [string]$Before) {
    if (Test-IsWindowsPlatform) {
        try { $handleIdentity = [MCAceFederationFileIdentityV4]::FromHandle($Stream.SafeFileHandle) }
        catch { throw "FABRIC_FEDERATION_GUI_HANDLE_IDENTITY_FAILED: $($_.Exception.Message)" }
        if ($handleIdentity -cne $Before) { throw 'FABRIC_FEDERATION_GUI_FILE_IDENTITY_CHANGED_BEFORE_READ' }
    }
    $after = Get-NoFollowFileIdentity $Path
    if ($after -cne $Before) { throw 'FABRIC_FEDERATION_GUI_FILE_IDENTITY_CHANGED_AFTER_READ' }
}

function Get-Crc32([byte[]]$Bytes, [int]$Offset, [int]$Count) {
    [uint32]$crc = [uint32]::MaxValue
    for ($i = 0; $i -lt $Count; $i++) {
        $crc = $crc -bxor [uint32]$Bytes[$Offset + $i]
        for ($bit = 0; $bit -lt 8; $bit++) {
            if (($crc -band 1) -ne 0) { $crc = ([uint32]($crc -shr 1)) -bxor [uint32]3988292384 }
            else { $crc = [uint32]($crc -shr 1) }
        }
    }
    return [uint32]($crc -bxor [uint32]::MaxValue)
}

function Get-Adler32([byte[]]$Bytes) {
    [uint32]$a = 1; [uint32]$b = 0
    foreach ($value in $Bytes) {
        $a = [uint32](($a + $value) % 65521)
        $b = [uint32](($b + $a) % 65521)
    }
    return [uint32](($b -shl 16) -bor $a)
}

function Expand-PngZlib([byte[]]$Compressed, [int]$MaximumBytes) {
    if ($Compressed.Length -lt 6) { throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_ZLIB_TRUNCATED' }
    $cmf = [int]$Compressed[0]; $flg = [int]$Compressed[1]
    if (($cmf -band 0x0f) -ne 8 -or ((($cmf -shl 8) + $flg) % 31) -ne 0 -or
            ($flg -band 0x20) -ne 0) {
        throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_ZLIB_HEADER_INVALID'
    }
    $deflateBytes = New-Object byte[] ($Compressed.Length - 6)
    [Array]::Copy($Compressed, 2, $deflateBytes, 0, $deflateBytes.Length)
    $input = [IO.MemoryStream]::new($deflateBytes, $false)
    $output = [IO.MemoryStream]::new()
    try {
        $deflate = [IO.Compression.DeflateStream]::new(
            $input, [IO.Compression.CompressionMode]::Decompress, $true)
        try {
            $buffer = New-Object byte[] 8192
            while (($read = $deflate.Read($buffer, 0, $buffer.Length)) -gt 0) {
                if ($output.Length + $read -gt $MaximumBytes) {
                    throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_DECODE_LIMIT_EXCEEDED'
                }
                $output.Write($buffer, 0, $read)
            }
        } finally { $deflate.Dispose() }
        $raw = $output.ToArray()
    } finally { $output.Dispose(); $input.Dispose() }
    $expected = Get-PngUInt32 $Compressed ($Compressed.Length - 4)
    if ((Get-Adler32 $raw) -ne $expected) {
        throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_ADLER32_INVALID'
    }
    return $raw
}

function Get-PaethPredictor([int]$A, [int]$B, [int]$C) {
    $p = $A + $B - $C; $pa = [Math]::Abs($p - $A); $pb = [Math]::Abs($p - $B); $pc = [Math]::Abs($p - $C)
    if ($pa -le $pb -and $pa -le $pc) { return $A }
    if ($pb -le $pc) { return $B }
    return $C
}

function Resolve-ExternalEvidenceOutputLeaf([string]$Path, [string]$Role) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [System.IO.Path]::IsPathRooted($Path)) {
        throw "FABRIC_FEDERATION_GUI_EXTERNAL_${Role}_ABSOLUTE_PATH_REQUIRED"
    }
    $full = [System.IO.Path]::GetFullPath($Path)
    $leaf = [System.IO.Path]::GetFileName($full)
    if ([string]::IsNullOrWhiteSpace($leaf) -or $leaf.Length -gt 128 -or
            $leaf -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw "FABRIC_FEDERATION_GUI_EXTERNAL_${Role}_LEAF_INVALID"
    }
    $parent = Assert-DirectLocalPath ([System.IO.Path]::GetDirectoryName($full)) -Directory
    if (-not [System.IO.Path]::GetDirectoryName($full).Equals(
            $parent, [StringComparison]::OrdinalIgnoreCase)) {
        throw "FABRIC_FEDERATION_GUI_EXTERNAL_${Role}_PARENT_INVALID"
    }
    return $full
}

function Wait-ExternalEvidenceLeaf([string]$Path, [int]$TimeoutSeconds, [string]$Role) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) { return }
        Start-Sleep -Milliseconds 100
    }
    throw "FABRIC_FEDERATION_GUI_EXTERNAL_${Role}_NOT_CREATED_IN_VISIBLE_WINDOW"
}

function Open-LockedBinaryEvidence([string]$Path) {
    $resolved = Assert-DirectLocalPath $Path
    $identityBefore = Get-NoFollowFileIdentity $resolved
    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $resolved, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read)
        if ($stream.Length -lt 128L -or $stream.Length -gt 20971520L) {
            throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_SIZE_INVALID'
        }
        $memory = [System.IO.MemoryStream]::new()
        try { $stream.CopyTo($memory); $bytes = $memory.ToArray() }
        finally { $memory.Dispose() }
        Assert-LockedFileIdentity $resolved $stream $identityBefore
        return [pscustomobject]@{
            bytes = $bytes
            sha256 = Get-BytesSha256 $bytes
            size_bytes = [long]$bytes.Length
            file_identity = $identityBefore
            stream = $stream
        }
    } catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}

function Open-LockedFileBytes([string]$Path, [long]$Minimum, [long]$Maximum, [string]$Role) {
    $resolved = Assert-DirectLocalPath $Path
    $identityBefore = Get-NoFollowFileIdentity $resolved
    $stream = $null
    try {
        $stream = [IO.File]::Open($resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($stream.Length -lt $Minimum -or $stream.Length -gt $Maximum) {
            throw "FABRIC_FEDERATION_GUI_${Role}_SIZE_INVALID"
        }
        $memory = [IO.MemoryStream]::new()
        try { $stream.CopyTo($memory); $bytes = $memory.ToArray() }
        finally { $memory.Dispose() }
        Assert-LockedFileIdentity $resolved $stream $identityBefore
        return [pscustomobject]@{
            absolute=$resolved; bytes=$bytes; sha256=Get-BytesSha256 $bytes
            size_bytes=[long]$bytes.Length; file_identity=$identityBefore; stream=$stream
        }
    } catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}

function Get-PngUInt32([byte[]]$Bytes, [int]$Offset) {
    if ($Offset -lt 0 -or $Offset + 4 -gt $Bytes.Length) {
        throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_TRUNCATED'
    }
    return [uint32](([uint32]$Bytes[$Offset] -shl 24) -bor
        ([uint32]$Bytes[$Offset + 1] -shl 16) -bor
        ([uint32]$Bytes[$Offset + 2] -shl 8) -bor [uint32]$Bytes[$Offset + 3])
}

function Assert-PngEvidence([byte[]]$Bytes) {
    $signature = [byte[]](0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a)
    if ($Bytes.Length -lt 33) { throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_TRUNCATED' }
    for ($index = 0; $index -lt $signature.Length; $index++) {
        if ($Bytes[$index] -ne $signature[$index]) {
            throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_SIGNATURE_INVALID'
        }
    }
    $offset = 8; $ihdrCount = 0; $iendCount = 0; $idatCount = 0
    $seenNonIdatAfterIdat = $false; $idat = [IO.MemoryStream]::new()
    $width = 0L; $height = 0L; $bitDepth = 0; $colorType = -1
    try {
        while ($offset -lt $Bytes.Length) {
            if ($offset + 12 -gt $Bytes.Length) { throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_TRUNCATED' }
            $length = [long](Get-PngUInt32 $Bytes $offset)
            if ($length -gt 20971520L -or $offset + 12L + $length -gt $Bytes.Length) {
                throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_CHUNK_LENGTH_INVALID'
            }
            $type = [Text.Encoding]::ASCII.GetString($Bytes, $offset + 4, 4)
            if ($type -cnotmatch '^[A-Za-z]{4}$') { throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_CHUNK_TYPE_INVALID' }
            $storedCrc = Get-PngUInt32 $Bytes ([int]($offset + 8 + $length))
            $computedCrc = Get-Crc32 $Bytes ($offset + 4) ([int]($length + 4))
            if ($storedCrc -ne $computedCrc) { throw "FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_CRC_INVALID: $type" }
            if ($type -ceq 'IHDR') {
                $ihdrCount++
                if ($ihdrCount -ne 1 -or $offset -ne 8 -or $length -ne 13) {
                    throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_IHDR_INVALID'
                }
                $width = [long](Get-PngUInt32 $Bytes ($offset + 8))
                $height = [long](Get-PngUInt32 $Bytes ($offset + 12))
                $bitDepth = [int]$Bytes[$offset + 16]
                $colorType = [int]$Bytes[$offset + 17]
                if ($Bytes[$offset + 18] -ne 0 -or $Bytes[$offset + 19] -ne 0 -or
                        $Bytes[$offset + 20] -ne 0 -or $bitDepth -ne 8 -or
                        $colorType -notin @(0,2,4,6)) {
                    throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_IHDR_FORMAT_UNSUPPORTED'
                }
            } elseif ($type -ceq 'IDAT') {
                if ($ihdrCount -ne 1 -or $iendCount -ne 0 -or $seenNonIdatAfterIdat) {
                    throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_IDAT_ORDER_INVALID'
                }
                $idatCount++
                $idat.Write($Bytes, $offset + 8, [int]$length)
            } elseif ($type -ceq 'IEND') {
                $iendCount++
                if ($iendCount -ne 1 -or $length -ne 0 -or $idatCount -lt 1 -or
                        $offset + 12 -ne $Bytes.Length) {
                    throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_IEND_INVALID'
                }
            } elseif ($idatCount -gt 0 -and $iendCount -eq 0) {
                $seenNonIdatAfterIdat = $true
            }
            $offset = [int]($offset + 12 + $length)
        }
        if ($ihdrCount -ne 1 -or $idatCount -lt 1 -or $iendCount -ne 1) {
            throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_REQUIRED_CHUNKS_MISSING'
        }
        if ($width -lt 320 -or $width -gt 8192 -or $height -lt 200 -or $height -gt 8192 -or
                $width * $height -gt 33554432) {
            throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_DIMENSIONS_INVALID'
        }
        $channels = switch ($colorType) { 0 { 1 } 2 { 3 } 4 { 2 } 6 { 4 } default { 0 } }
        $rowBytes = [long]$width * $channels
        $expectedInflated = ($rowBytes + 1L) * $height
        if ($expectedInflated -gt 134217728L) { throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_DECODE_LIMIT_EXCEEDED' }
        $inflated = Expand-PngZlib $idat.ToArray() ([int]$expectedInflated)
        if ($inflated.Length -ne $expectedInflated) { throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_SCANLINE_LENGTH_INVALID' }
        $pixels = New-Object byte[] ([int]($rowBytes * $height))
        $sourceOffset = 0; $destinationOffset = 0; $bytesPerPixel = $channels
        for ($row = 0; $row -lt $height; $row++) {
            $filter = [int]$inflated[$sourceOffset++]
            if ($filter -lt 0 -or $filter -gt 4) { throw 'FABRIC_FEDERATION_GUI_SCREENSHOT_PNG_FILTER_INVALID' }
            for ($column = 0; $column -lt $rowBytes; $column++) {
                $rawValue = [int]$inflated[$sourceOffset++]
                $left = if ($column -ge $bytesPerPixel) { [int]$pixels[$destinationOffset + $column - $bytesPerPixel] } else { 0 }
                $up = if ($row -gt 0) { [int]$pixels[$destinationOffset + $column - $rowBytes] } else { 0 }
                $upLeft = if ($row -gt 0 -and $column -ge $bytesPerPixel) {
                    [int]$pixels[$destinationOffset + $column - $rowBytes - $bytesPerPixel]
                } else { 0 }
                $predictor = switch ($filter) {
                    0 { 0 }
                    1 { $left }
                    2 { $up }
                    3 { [Math]::Floor(($left + $up) / 2) }
                    4 { Get-PaethPredictor $left $up $upLeft }
                }
                $pixels[$destinationOffset + $column] = [byte](($rawValue + [int]$predictor) -band 0xff)
            }
            $destinationOffset += [int]$rowBytes
        }
        return [pscustomobject]@{
            width = [int]$width
            height = [int]$height
            color_type = $colorType
            decoded_pixel_sha256 = Get-BytesSha256 $pixels
        }
    } finally { $idat.Dispose() }
}

$visibleGuiSigningRequestPropertyNames = @(
    'schema','domain','artifact_class','source_mode','attestation_schema',
    'attestation_artifact_class','attestation_source_mode','attestation_tool',
    'attestation_signing_domain','attestation_payload_format','attestation_property_order_csv',
    'attestation_required_assertions','attestation_publish_mode','attestation_test_fixture',
    'source_commit',
    'artifact_source_commit','product_version','fabric_target','source_proxy','target_proxy',
    'release_bundle_manifest_sha256','final_fabric_jar_file','final_fabric_jar_sha256',
    'final_fabric_jar_size_bytes','client_build_id','run_attempt_id','gui_attempt_id',
    'challenge_nonce','challenge_issued_at','prompt_rendered_at','request_created_at','expires_at',
    'client_process_id','client_process_started_at','path_canonicalization',
    'signing_request_file','signing_request_path_sha256','screenshot_file',
    'screenshot_path_sha256','screenshot_freeze_mode','screenshot_sha256',
    'screenshot_size_bytes','screenshot_width',
    'screenshot_height','screenshot_decoded_pixel_sha256','attestation_output_file',
    'attestation_output_path_sha256','signer_key_id','signer_trust_root_sha256',
    'signature_algorithm','test_fixture'
)
$visibleGuiAttestationPropertyNames = @(
    'schema','artifact_class','source_mode','tool','session_id','window_id',
    'client_process_id','client_process_started_at','attempt_id','gui_attempt_id','challenge_nonce',
    'challenge_issued_at','captured_at','signed_at','source_commit','fabric_target',
    'final_fabric_jar_sha256','signing_request_schema','signing_request_sha256',
    'screenshot_file','screenshot_sha256','screenshot_size_bytes',
    'screenshot_width','screenshot_height','screenshot_decoded_pixel_sha256',
    'prompt_challenge_visible','operator_attested_visible_session',
    'operator_attested_no_headless_or_synthetic_input','signer_key_id',
    'signer_trust_root_sha256','signature_algorithm','test_fixture','signature_base64'
)
$visibleGuiTrustRootPropertyNames = @(
    'schema','artifact_class','key_id','algorithm','modulus_base64','exponent_base64','test_fixture'
)

function Get-VisibleGuiAttestationSigningPayload([object]$Attestation) {
    $ordered = @($visibleGuiAttestationPropertyNames | Where-Object { $_ -cne 'signature_base64' })
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add($visibleGuiAttestationSigningDomain)
    foreach ($name in $ordered) {
        $value = $Attestation.$name
        if ($value -is [bool]) { $rendered = if ([bool]$value) { 'true' } else { 'false' } }
        elseif ($value -is [byte] -or $value -is [sbyte] -or $value -is [int16] -or
                $value -is [uint16] -or $value -is [int32] -or $value -is [uint32] -or
                $value -is [int64] -or $value -is [uint64]) {
            $rendered = [Convert]::ToString($value, [Globalization.CultureInfo]::InvariantCulture)
        } else { $rendered = [string]$value }
        if ($rendered -match '[\r\n]' -or $name -match '[\r\n=]') {
            throw 'FABRIC_FEDERATION_GUI_EXTERNAL_ATTESTATION_SIGNING_VALUE_INVALID'
        }
        $lines.Add("$name=$rendered")
    }
    return [Text.UTF8Encoding]::new($false).GetBytes(($lines -join "`n") + "`n")
}

function Get-CanonicalExchangePathBinding([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) {
        throw 'FABRIC_FEDERATION_GUI_EXCHANGE_ABSOLUTE_PATH_REQUIRED'
    }
    $full = [IO.Path]::GetFullPath($Path)
    if (Test-IsWindowsPlatform) {
        $canonicalization = 'WINDOWS_FULL_PATH_LOWER_BACKSLASH_UTF8_SHA256_V1'
        $canonical = $full.Replace('/', '\').ToLowerInvariant()
    } else {
        $canonicalization = 'PORTABLE_FULL_PATH_ORDINAL_UTF8_SHA256_V1'
        $canonical = $full
    }
    return [pscustomobject]@{
        canonicalization = $canonicalization
        sha256 = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($canonical))
    }
}

function Assert-VisibleGuiSigningRequest(
        [object]$Evidence,
        [object]$Screenshot,
        [System.Collections.IDictionary]$Expected,
        [DateTimeOffset]$CurrentTime,
        [switch]$AllowTestFixture) {
    $request = ConvertFrom-StrictJson $Evidence.raw
    if (-not (Test-ExactJsonProperties $request $visibleGuiSigningRequestPropertyNames)) {
        throw 'FABRIC_FEDERATION_GUI_SIGNING_REQUEST_SCHEMA_INVALID'
    }
    foreach ($name in @(
            'schema','domain','artifact_class','source_mode','attestation_schema',
            'attestation_artifact_class','attestation_source_mode','attestation_tool',
            'attestation_signing_domain','attestation_payload_format',
            'attestation_property_order_csv','attestation_required_assertions',
            'attestation_publish_mode','source_commit',
            'artifact_source_commit','product_version','fabric_target','source_proxy','target_proxy',
            'release_bundle_manifest_sha256','final_fabric_jar_file','final_fabric_jar_sha256',
            'client_build_id','run_attempt_id','gui_attempt_id','challenge_nonce',
            'challenge_issued_at','prompt_rendered_at','request_created_at','expires_at',
            'client_process_started_at',
            'path_canonicalization','signing_request_file','signing_request_path_sha256',
            'screenshot_file','screenshot_path_sha256','screenshot_freeze_mode','screenshot_sha256',
            'screenshot_decoded_pixel_sha256','attestation_output_file',
            'attestation_output_path_sha256','signer_key_id','signer_trust_root_sha256',
            'signature_algorithm')) {
        if (-not (Test-JsonString $request.$name)) {
            throw "FABRIC_FEDERATION_GUI_SIGNING_REQUEST_TYPE_INVALID: $name"
        }
    }
    foreach ($name in @('final_fabric_jar_size_bytes','client_process_id','screenshot_size_bytes',
            'screenshot_width','screenshot_height')) {
        if (-not (Test-JsonInteger $request.$name)) {
            throw "FABRIC_FEDERATION_GUI_SIGNING_REQUEST_INTEGER_TYPE_INVALID: $name"
        }
    }
    if (-not (Test-JsonBoolean $request.test_fixture) -or
            -not (Test-JsonBoolean $request.attestation_test_fixture)) {
        throw 'FABRIC_FEDERATION_GUI_SIGNING_REQUEST_BOOLEAN_TYPE_INVALID'
    }
    if ([bool]$request.test_fixture) {
        if (-not $AllowTestFixture -or
                $request.artifact_class -cne 'TEST_VISIBLE_GUI_SIGNING_REQUEST_FIXTURE' -or
                $request.source_mode -cne 'TEST_NOFOLLOW_ATOMIC_EXCHANGE_FIXTURE' -or
                -not [bool]$request.attestation_test_fixture -or
                $request.attestation_artifact_class -cne 'TEST_SIGNED_GUI_ATTESTATION_FIXTURE' -or
                $request.attestation_source_mode -cne 'TEST_SIGNED_PARSER_FIXTURE') {
            throw 'FABRIC_FEDERATION_GUI_TEST_SIGNING_REQUEST_RELEASE_REJECTED'
        }
    } elseif ($request.artifact_class -cne $visibleGuiSigningRequestArtifactClass -or
            $request.source_mode -cne $visibleGuiSigningRequestSourceMode -or
            [bool]$request.attestation_test_fixture -or
            $request.attestation_artifact_class -cne $visibleGuiAttestationArtifactClass -or
            $request.attestation_source_mode -cne $visibleGuiAttestationSourceMode) {
        throw 'FABRIC_FEDERATION_GUI_SIGNING_REQUEST_PROVENANCE_INVALID'
    }
    if ($request.schema -cne $visibleGuiSigningRequestSchema -or
            $request.domain -cne $visibleGuiSigningRequestDomain -or
            $request.attestation_schema -cne $visibleGuiAttestationSchema -or
            $request.attestation_artifact_class -notin @(
                $visibleGuiAttestationArtifactClass,'TEST_SIGNED_GUI_ATTESTATION_FIXTURE') -or
            $request.attestation_source_mode -notin @(
                $visibleGuiAttestationSourceMode,'TEST_SIGNED_PARSER_FIXTURE') -or
            $request.attestation_tool -cne 'computer-use' -or
            $request.attestation_signing_domain -cne $visibleGuiAttestationSigningDomain -or
            $request.attestation_payload_format -cne 'LF_KEY_EQUALS_VALUE_UTF8_FINAL_LF_V1' -or
            $request.attestation_property_order_csv -cne ($visibleGuiAttestationPropertyNames -join ',') -or
            $request.attestation_required_assertions -cne
                'prompt_challenge_visible=true,operator_attested_visible_session=true,operator_attested_no_headless_or_synthetic_input=true' -or
            $request.attestation_publish_mode -cne
                'ATOMIC_CREATE_NEW_COMPLETE_JSON_THEN_CLOSE_V1' -or
            $request.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
            $request.artifact_source_commit -cnotmatch '^[0-9a-f]{40}$' -or
            $request.product_version -cne '0.0.1' -or
            $request.fabric_target -notin @('1.21.11','26.1.2','26.2') -or
            $request.source_proxy -notin @('VELOCITY','BUNGEE') -or
            $request.target_proxy -notin @('VELOCITY','BUNGEE') -or
            -not (Test-Sha256 $request.release_bundle_manifest_sha256) -or
            -not (Test-Sha256 $request.final_fabric_jar_sha256) -or
            [long]$request.final_fabric_jar_size_bytes -le 0 -or
            $request.run_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            $request.gui_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            $request.challenge_nonce -cnotmatch '^[0-9a-f]{64}$' -or
            $request.signing_request_path_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $request.screenshot_path_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $request.attestation_output_path_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $request.screenshot_freeze_mode -cne 'PRECLICK_FILESHARE_READ_LOCK_UNTIL_ACCEPT_V1' -or
            $request.signer_trust_root_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $request.signature_algorithm -cne 'RSA_PKCS1_SHA256') {
        throw 'FABRIC_FEDERATION_GUI_SIGNING_REQUEST_BINDING_INVALID'
    }
    foreach ($name in $visibleGuiSigningRequestPropertyNames) {
        if (-not $Expected.Contains($name)) {
            throw "FABRIC_FEDERATION_GUI_SIGNING_REQUEST_EXPECTED_FIELD_MISSING: $name"
        }
        if ([string]$request.$name -cne [string]$Expected[$name]) {
            throw "FABRIC_FEDERATION_GUI_SIGNING_REQUEST_EXPECTED_MISMATCH: $name"
        }
    }
    $times = @{}
    foreach ($name in @('challenge_issued_at','prompt_rendered_at','request_created_at','expires_at',
            'client_process_started_at')) {
        $parsed = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParseExact([string]$request.$name, 'o',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::None, [ref]$parsed)) {
            throw "FABRIC_FEDERATION_GUI_SIGNING_REQUEST_TIMESTAMP_INVALID: $name"
        }
        $times[$name] = $parsed.ToUniversalTime()
    }
    if ($times.challenge_issued_at.Ticks -gt $times.prompt_rendered_at.Ticks -or
            $times.client_process_started_at.Ticks -gt $times.prompt_rendered_at.Ticks -or
            $times.request_created_at.Ticks -lt $times.prompt_rendered_at.Ticks -or
            $times.request_created_at.Ticks -gt $times.expires_at.Ticks -or
            $times.expires_at.Ticks -le $times.prompt_rendered_at.Ticks -or
            ($times.expires_at - $times.challenge_issued_at).TotalMinutes -gt 15 -or
            ($times.expires_at - $times.prompt_rendered_at).TotalMinutes -gt 3 -or
            $CurrentTime.ToUniversalTime().Ticks -lt $times.request_created_at.Ticks -or
            $CurrentTime.ToUniversalTime().Ticks -gt $times.expires_at.Ticks) {
        throw 'FABRIC_FEDERATION_GUI_SIGNING_REQUEST_EXPIRED_OR_TIME_INVALID'
    }
    $png = Assert-PngEvidence $Screenshot.bytes
    if ($request.screenshot_sha256 -cne $Screenshot.sha256 -or
            [long]$request.screenshot_size_bytes -ne [long]$Screenshot.size_bytes -or
            [int]$request.screenshot_width -ne [int]$png.width -or
            [int]$request.screenshot_height -ne [int]$png.height -or
            $request.screenshot_decoded_pixel_sha256 -cne $png.decoded_pixel_sha256) {
        throw 'FABRIC_FEDERATION_GUI_SIGNING_REQUEST_SCREENSHOT_BINDING_INVALID'
    }
    return [pscustomobject]@{
        value = $request
        expires_at = $times.expires_at.ToString('o')
        screenshot_width = [int]$png.width
        screenshot_height = [int]$png.height
        screenshot_decoded_pixel_sha256 = [string]$png.decoded_pixel_sha256
        sha256 = [string]$Evidence.sha256
    }
}

function Assert-VisibleGuiTrustRoot(
        [object]$TrustRootEvidence,
        [string]$ExpectedSha256,
        [string]$ApprovedSha256 = '',
        [switch]$AllowTestFixture) {
    if ($TrustRootEvidence.sha256 -cne $ExpectedSha256.ToLowerInvariant()) {
        throw 'FABRIC_FEDERATION_GUI_TRUST_ROOT_PIN_MISMATCH'
    }
    if ([string]::IsNullOrWhiteSpace($ApprovedSha256)) {
        if (-not $AllowTestFixture) {
            throw 'FABRIC_FEDERATION_GUI_APPROVED_TRUST_ROOT_PIN_REQUIRED'
        }
    } elseif ($ApprovedSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
            $ExpectedSha256.ToLowerInvariant() -cne $ApprovedSha256.ToLowerInvariant()) {
        throw 'FABRIC_FEDERATION_GUI_TRUST_ROOT_NOT_APPROVED'
    }
    $root = ConvertFrom-StrictJson $TrustRootEvidence.raw
    if (-not (Test-ExactJsonProperties $root $visibleGuiTrustRootPropertyNames) -or
            $root.schema -cne $visibleGuiTrustRootSchema -or
            $root.algorithm -cne 'RSA_PKCS1_SHA256' -or
            $root.key_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$' -or
            -not (Test-JsonBoolean $root.test_fixture)) {
        throw 'FABRIC_FEDERATION_GUI_TRUST_ROOT_SCHEMA_INVALID'
    }
    if ([bool]$root.test_fixture) {
        if (-not $AllowTestFixture -or $root.artifact_class -cne 'TEST_GUI_SIGNING_TRUST_ROOT_FIXTURE') {
            throw 'FABRIC_FEDERATION_GUI_TEST_TRUST_ROOT_RELEASE_REJECTED'
        }
    } elseif ($root.artifact_class -cne 'OUT_OF_BAND_PINNED_GUI_SIGNING_TRUST_ROOT') {
        throw 'FABRIC_FEDERATION_GUI_TRUST_ROOT_PROVENANCE_INVALID'
    }
    try {
        $modulus = [Convert]::FromBase64String([string]$root.modulus_base64)
        $exponent = [Convert]::FromBase64String([string]$root.exponent_base64)
    } catch { throw 'FABRIC_FEDERATION_GUI_TRUST_ROOT_KEY_ENCODING_INVALID' }
    if ($modulus.Length -lt 256 -or $modulus.Length -gt 512 -or
            $exponent.Length -lt 1 -or $exponent.Length -gt 4) {
        throw 'FABRIC_FEDERATION_GUI_TRUST_ROOT_KEY_SIZE_INVALID'
    }
    return [pscustomobject]@{ value=$root; modulus=$modulus; exponent=$exponent }
}

function Test-RsaPkcs1Sha256Signature(
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

function Assert-VisibleGuiAttestation(
        [object]$Evidence,
        [object]$Screenshot,
        [object]$SigningRequestEvidence,
        [object]$ValidatedSigningRequest,
        [object]$TrustRootEvidence,
        [string]$ExpectedTrustRootSha256,
        [DateTimeOffset]$PromptRenderedAt,
        [DateTimeOffset]$EnablementAcceptedAt,
        [string]$ExpectedSourceCommit,
        [string]$ExpectedFabricTarget,
        [string]$ExpectedFabricArtifactSha256,
        [string]$ExpectedAttemptId,
        [string]$ExpectedGuiAttemptId,
        [string]$ExpectedChallengeNonce,
        [DateTimeOffset]$ExpectedChallengeIssuedAt,
        [int]$ExpectedClientProcessId,
        [string]$ExpectedClientProcessStartedAt,
        [string]$ApprovedTrustRootSha256 = '',
        [switch]$AllowTestFixture) {
    $attestation = ConvertFrom-StrictJson $Evidence.raw
    if (-not (Test-ExactJsonProperties $attestation $visibleGuiAttestationPropertyNames)) {
        throw 'FABRIC_FEDERATION_GUI_EXTERNAL_ATTESTATION_SCHEMA_INVALID'
    }
    foreach ($name in @('schema','artifact_class','source_mode','tool','session_id','window_id',
            'client_process_started_at','attempt_id','gui_attempt_id','challenge_nonce','challenge_issued_at',
            'captured_at','signed_at','source_commit','fabric_target','final_fabric_jar_sha256',
            'signing_request_schema','signing_request_sha256','screenshot_file','screenshot_sha256',
            'screenshot_decoded_pixel_sha256','signer_key_id',
            'signer_trust_root_sha256','signature_algorithm','signature_base64')) {
        if (-not (Test-JsonString $attestation.$name)) {
            throw "FABRIC_FEDERATION_GUI_EXTERNAL_ATTESTATION_TYPE_INVALID: $name"
        }
    }
    foreach ($name in @('client_process_id','screenshot_size_bytes','screenshot_width','screenshot_height')) {
        if (-not (Test-JsonInteger $attestation.$name)) {
            throw "FABRIC_FEDERATION_GUI_EXTERNAL_ATTESTATION_INTEGER_TYPE_INVALID: $name"
        }
    }
    foreach ($name in @('prompt_challenge_visible','operator_attested_visible_session',
            'operator_attested_no_headless_or_synthetic_input','test_fixture')) {
        if (-not (Test-JsonBoolean $attestation.$name)) {
            throw "FABRIC_FEDERATION_GUI_EXTERNAL_ATTESTATION_BOOLEAN_TYPE_INVALID: $name"
        }
    }
    $isFixture = [bool]$attestation.test_fixture
    $validatedTrustRoot = Assert-VisibleGuiTrustRoot $TrustRootEvidence `
        $ExpectedTrustRootSha256 $ApprovedTrustRootSha256 -AllowTestFixture:$AllowTestFixture
    if ($isFixture) {
        if (-not $AllowTestFixture -or
                $attestation.artifact_class -cne 'TEST_SIGNED_GUI_ATTESTATION_FIXTURE' -or
                $attestation.source_mode -cne 'TEST_SIGNED_PARSER_FIXTURE' -or
                -not [bool]$validatedTrustRoot.value.test_fixture) {
            throw 'FABRIC_FEDERATION_GUI_TEST_ATTESTATION_FIXTURE_RELEASE_REJECTED'
        }
    } elseif ($attestation.artifact_class -cne $visibleGuiAttestationArtifactClass -or
            $attestation.source_mode -cne $visibleGuiAttestationSourceMode) {
        throw 'FABRIC_FEDERATION_GUI_EXTERNAL_ATTESTATION_PROVENANCE_INVALID'
    }
    if ($attestation.schema -cne $visibleGuiAttestationSchema -or
            $attestation.tool -cne 'computer-use' -or
            $attestation.session_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$' -or
            $attestation.window_id -cnotmatch '^(?:0x)?[0-9a-fA-F]{1,16}$' -or
            $ExpectedClientProcessId -le 0 -or
            [int]$attestation.client_process_id -ne $ExpectedClientProcessId -or
            $attestation.client_process_started_at -cne $ExpectedClientProcessStartedAt -or
            $attestation.attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            $attestation.attempt_id -cne $ExpectedAttemptId -or
            $attestation.gui_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            $attestation.gui_attempt_id -cne $ExpectedGuiAttemptId -or
            $attestation.challenge_nonce -cnotmatch '^[0-9a-f]{64}$' -or
            $attestation.challenge_nonce -cne $ExpectedChallengeNonce -or
            $attestation.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
            $attestation.source_commit -cne $ExpectedSourceCommit -or
            $attestation.fabric_target -cne $ExpectedFabricTarget -or
            -not (Test-Sha256 $attestation.final_fabric_jar_sha256) -or
            $attestation.final_fabric_jar_sha256 -cne $ExpectedFabricArtifactSha256 -or
            $attestation.signing_request_schema -cne $visibleGuiSigningRequestSchema -or
            $attestation.signing_request_sha256 -cne [string]$SigningRequestEvidence.sha256 -or
            $attestation.signing_request_sha256 -cne [string]$ValidatedSigningRequest.sha256 -or
            $attestation.signer_key_id -cne [string]$validatedTrustRoot.value.key_id -or
            $attestation.signer_trust_root_sha256 -cne $ExpectedTrustRootSha256.ToLowerInvariant() -or
            $attestation.signature_algorithm -cne 'RSA_PKCS1_SHA256' -or
            -not [bool]$attestation.prompt_challenge_visible -or
            -not [bool]$attestation.operator_attested_visible_session -or
            -not [bool]$attestation.operator_attested_no_headless_or_synthetic_input) {
        throw 'FABRIC_FEDERATION_GUI_EXTERNAL_ATTESTATION_BINDING_INVALID'
    }
    if ($ValidatedSigningRequest.value.run_attempt_id -cne $attestation.attempt_id -or
            $ValidatedSigningRequest.value.gui_attempt_id -cne $attestation.gui_attempt_id -or
            $ValidatedSigningRequest.value.challenge_nonce -cne $attestation.challenge_nonce -or
            $ValidatedSigningRequest.value.challenge_issued_at -cne $attestation.challenge_issued_at -or
            $ValidatedSigningRequest.value.source_commit -cne $attestation.source_commit -or
            $ValidatedSigningRequest.value.fabric_target -cne $attestation.fabric_target -or
            $ValidatedSigningRequest.value.final_fabric_jar_sha256 -cne
                $attestation.final_fabric_jar_sha256 -or
            $ValidatedSigningRequest.value.screenshot_file -cne $attestation.screenshot_file -or
            $ValidatedSigningRequest.value.screenshot_sha256 -cne $attestation.screenshot_sha256 -or
            [long]$ValidatedSigningRequest.value.screenshot_size_bytes -ne
                [long]$attestation.screenshot_size_bytes -or
            [int]$ValidatedSigningRequest.value.screenshot_width -ne
                [int]$attestation.screenshot_width -or
            [int]$ValidatedSigningRequest.value.screenshot_height -ne
                [int]$attestation.screenshot_height -or
            $ValidatedSigningRequest.value.screenshot_decoded_pixel_sha256 -cne
                $attestation.screenshot_decoded_pixel_sha256 -or
            $ValidatedSigningRequest.value.signer_key_id -cne $attestation.signer_key_id -or
            $ValidatedSigningRequest.value.signer_trust_root_sha256 -cne
                $attestation.signer_trust_root_sha256) {
        throw 'FABRIC_FEDERATION_GUI_ATTESTATION_SIGNING_REQUEST_BINDING_INVALID'
    }
    $times = @{}
    foreach ($name in @('challenge_issued_at','captured_at','signed_at','client_process_started_at')) {
        $parsed = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParseExact([string]$attestation.$name, 'o',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::None, [ref]$parsed)) {
            throw "FABRIC_FEDERATION_GUI_EXTERNAL_ATTESTATION_TIMESTAMP_INVALID: $name"
        }
        $times[$name] = $parsed.ToUniversalTime()
    }
    if ($times.challenge_issued_at.Ticks -ne $ExpectedChallengeIssuedAt.ToUniversalTime().Ticks -or
            $times.client_process_started_at.Ticks -gt $PromptRenderedAt.ToUniversalTime().Ticks -or
            $times.captured_at.Ticks -lt $PromptRenderedAt.ToUniversalTime().Ticks -or
            $times.captured_at.Ticks -gt $EnablementAcceptedAt.ToUniversalTime().Ticks -or
            $times.signed_at.Ticks -lt $times.captured_at.Ticks -or
            $times.captured_at.Ticks -gt ([DateTimeOffset]::ParseExact(
                [string]$ValidatedSigningRequest.value.request_created_at, 'o',
                [Globalization.CultureInfo]::InvariantCulture)).ToUniversalTime().Ticks -or
            $times.signed_at.Ticks -lt ([DateTimeOffset]::ParseExact(
                [string]$ValidatedSigningRequest.value.request_created_at, 'o',
                [Globalization.CultureInfo]::InvariantCulture)).ToUniversalTime().Ticks -or
            $times.signed_at.Ticks -gt $EnablementAcceptedAt.ToUniversalTime().Ticks -or
            $times.challenge_issued_at.Ticks -gt $PromptRenderedAt.ToUniversalTime().Ticks -or
            $times.signed_at.Ticks -gt ([DateTimeOffset]::ParseExact(
                [string]$ValidatedSigningRequest.value.expires_at, 'o',
                [Globalization.CultureInfo]::InvariantCulture)).ToUniversalTime().Ticks) {
        throw 'FABRIC_FEDERATION_GUI_EXTERNAL_ATTESTATION_CAPTURE_WINDOW_INVALID'
    }
    $png = Assert-PngEvidence $Screenshot.bytes
    if ($attestation.screenshot_sha256 -cne $Screenshot.sha256 -or
            [long]$attestation.screenshot_size_bytes -ne [long]$Screenshot.size_bytes -or
            [int]$attestation.screenshot_width -ne [int]$png.width -or
            [int]$attestation.screenshot_height -ne [int]$png.height -or
            $attestation.screenshot_decoded_pixel_sha256 -cne $png.decoded_pixel_sha256) {
        throw 'FABRIC_FEDERATION_GUI_EXTERNAL_ATTESTATION_SCREENSHOT_BINDING_INVALID'
    }
    try { $signature = [Convert]::FromBase64String([string]$attestation.signature_base64) }
    catch { throw 'FABRIC_FEDERATION_GUI_EXTERNAL_ATTESTATION_SIGNATURE_ENCODING_INVALID' }
    if ($signature.Length -ne $validatedTrustRoot.modulus.Length -or
            -not (Test-RsaPkcs1Sha256Signature `
                (Get-VisibleGuiAttestationSigningPayload $attestation) $signature `
                $validatedTrustRoot.modulus $validatedTrustRoot.exponent)) {
        throw 'FABRIC_FEDERATION_GUI_EXTERNAL_ATTESTATION_SIGNATURE_INVALID'
    }
    return [pscustomobject]@{
        value = $attestation
        captured_at = $times.captured_at.ToString('o')
        signed_at = $times.signed_at.ToString('o')
        screenshot_width = [int]$png.width
        screenshot_height = [int]$png.height
        screenshot_decoded_pixel_sha256 = [string]$png.decoded_pixel_sha256
        trust_root_key_id = [string]$validatedTrustRoot.value.key_id
    }
}

function Get-ApprovedReleaseSignerPin([string]$EnvironmentName, [string]$Role) {
    $value = [Environment]::GetEnvironmentVariable($EnvironmentName, 'Process')
    if ([string]::IsNullOrWhiteSpace($value) -or $value -cnotmatch '^[0-9a-fA-F]{64}$') {
        throw "FABRIC_FEDERATION_GUI_APPROVED_${Role}_PIN_REQUIRED"
    }
    return $value.ToLowerInvariant()
}

$postRunTrustRootPropertyNames = @(
    'schema','artifact_class','key_id','algorithm','modulus_base64','exponent_base64','test_fixture'
)
$postRunReceiptPropertyNames = @(
    'schema','artifact_class','source_mode','signed_at','release_source_commit',
    'artifact_source_commit','product_version','fabric_target','source_proxy','target_proxy',
    'release_bundle_manifest_sha256','release_bundle_fabric_jar_sha256',
    'release_bundle_paper_jar_sha256','release_bundle_source_proxy_jar_sha256',
    'release_bundle_target_proxy_jar_sha256','run_attempt_id','gui_challenge_nonce',
    'postrun_operation_attempt_id','postrun_challenge_nonce','postrun_challenge_issued_at',
    'supervisor_process_incarnation_id','source_proxy_process_incarnation_id',
    'target_proxy_process_incarnation_id','source_paper_process_incarnation_id',
    'target_paper_process_incarnation_id','fabric_client_process_incarnation_id',
    'visible_gui_attestation_sha256','visible_gui_screenshot_sha256',
    'visible_gui_screenshot_decoded_pixel_sha256','runtime_ledger_sha256',
    'runtime_ledger_size_bytes','runtime_ledger_head_sha256',
    'runtime_ledger_supervisor_seal_sha256','runtime_ledger_event_count',
    'report_sha256','report_size_bytes','binding_sha256','binding_size_bytes',
    'signer_key_id','signer_trust_root_sha256','signature_algorithm','test_fixture','signature_base64'
)

function Get-PostRunReceiptSigningPayload([object]$Receipt) {
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('MCACE_FABRIC_FEDERATION_POSTRUN_RECEIPT_SIGNING_V1')
    foreach ($name in @($postRunReceiptPropertyNames | Where-Object { $_ -cne 'signature_base64' })) {
        $value = $Receipt.$name
        if ($value -is [bool]) { $rendered = if ([bool]$value) { 'true' } else { 'false' } }
        elseif ($value -is [byte] -or $value -is [sbyte] -or $value -is [int16] -or
                $value -is [uint16] -or $value -is [int32] -or $value -is [uint32] -or
                $value -is [int64] -or $value -is [uint64]) {
            $rendered = [Convert]::ToString($value, [Globalization.CultureInfo]::InvariantCulture)
        } else { $rendered = [string]$value }
        if ($rendered -match '[\r\n]' -or $name -match '[\r\n=]') {
            throw 'FABRIC_FEDERATION_GUI_POSTRUN_SIGNING_VALUE_INVALID'
        }
        $lines.Add("$name=$rendered")
    }
    return [Text.UTF8Encoding]::new($false).GetBytes(($lines -join "`n") + "`n")
}

function Assert-PostRunSupervisorTrustRoot(
        [object]$TrustRootEvidence,
        [string]$ExpectedSha256,
        [string]$ApprovedSha256 = '',
        [switch]$AllowTestFixture) {
    if ($TrustRootEvidence.sha256 -cne $ExpectedSha256.ToLowerInvariant()) {
        throw 'FABRIC_FEDERATION_GUI_POSTRUN_TRUST_ROOT_PIN_MISMATCH'
    }
    if ([string]::IsNullOrWhiteSpace($ApprovedSha256)) {
        if (-not $AllowTestFixture) {
            throw 'FABRIC_FEDERATION_GUI_APPROVED_POSTRUN_PIN_REQUIRED'
        }
    } elseif ($ApprovedSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
            $ExpectedSha256.ToLowerInvariant() -cne $ApprovedSha256.ToLowerInvariant()) {
        throw 'FABRIC_FEDERATION_GUI_POSTRUN_TRUST_ROOT_NOT_APPROVED'
    }
    $root = ConvertFrom-StrictJson $TrustRootEvidence.raw
    if (-not (Test-ExactJsonProperties $root $postRunTrustRootPropertyNames) -or
            $root.schema -cne $postRunTrustRootSchema -or
            $root.algorithm -cne 'RSA_PKCS1_SHA256' -or
            $root.key_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$' -or
            -not (Test-JsonBoolean $root.test_fixture)) {
        throw 'FABRIC_FEDERATION_GUI_POSTRUN_TRUST_ROOT_SCHEMA_INVALID'
    }
    if ([bool]$root.test_fixture) {
        if (-not $AllowTestFixture -or
                $root.artifact_class -cne 'TEST_FEDERATION_POSTRUN_SIGNING_TRUST_ROOT_FIXTURE') {
            throw 'FABRIC_FEDERATION_GUI_TEST_POSTRUN_TRUST_ROOT_RELEASE_REJECTED'
        }
    } elseif ($root.artifact_class -cne
            'OUT_OF_BAND_PINNED_FEDERATION_POSTRUN_SIGNING_TRUST_ROOT') {
        throw 'FABRIC_FEDERATION_GUI_POSTRUN_TRUST_ROOT_PROVENANCE_INVALID'
    }
    try {
        $modulus = [Convert]::FromBase64String([string]$root.modulus_base64)
        $exponent = [Convert]::FromBase64String([string]$root.exponent_base64)
    } catch { throw 'FABRIC_FEDERATION_GUI_POSTRUN_TRUST_ROOT_KEY_ENCODING_INVALID' }
    if ($modulus.Length -lt 256 -or $modulus.Length -gt 512 -or
            $exponent.Length -lt 1 -or $exponent.Length -gt 4) {
        throw 'FABRIC_FEDERATION_GUI_POSTRUN_TRUST_ROOT_KEY_SIZE_INVALID'
    }
    return [pscustomobject]@{ value=$root; modulus=$modulus; exponent=$exponent }
}

function Assert-DistinctFederationSignerRoots([object]$GuiRoot, [object]$PostRunRoot) {
    if ([string]$GuiRoot.value.key_id -ceq [string]$PostRunRoot.value.key_id -or
            [string]$GuiRoot.value.modulus_base64 -ceq [string]$PostRunRoot.value.modulus_base64 -or
            ([string]$GuiRoot.value.modulus_base64 + ':' + [string]$GuiRoot.value.exponent_base64) -ceq
            ([string]$PostRunRoot.value.modulus_base64 + ':' + [string]$PostRunRoot.value.exponent_base64)) {
        throw 'FABRIC_FEDERATION_GUI_SIGNER_KEYS_MUST_DIFFER'
    }
}

function Assert-PostRunReceipt(
        [object]$Evidence,
        [object]$TrustRootEvidence,
        [string]$ExpectedTrustRootSha256,
        [string]$ApprovedTrustRootSha256,
        [System.Collections.IDictionary]$Expected,
        [DateTimeOffset]$ChallengeIssuedAt,
        [switch]$AllowTestFixture) {
    $receipt = ConvertFrom-StrictJson $Evidence.raw
    if (-not (Test-ExactJsonProperties $receipt $postRunReceiptPropertyNames)) {
        throw 'FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_SCHEMA_INVALID'
    }
    foreach ($name in @($postRunReceiptPropertyNames | Where-Object {
            $_ -notin @('runtime_ledger_size_bytes','runtime_ledger_event_count',
                'report_size_bytes','binding_size_bytes','test_fixture') })) {
        if (-not (Test-JsonString $receipt.$name)) {
            throw "FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_TYPE_INVALID: $name"
        }
    }
    foreach ($name in @('runtime_ledger_size_bytes','runtime_ledger_event_count',
            'report_size_bytes','binding_size_bytes')) {
        if (-not (Test-JsonInteger $receipt.$name)) {
            throw "FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_INTEGER_TYPE_INVALID: $name"
        }
    }
    if (-not (Test-JsonBoolean $receipt.test_fixture)) {
        throw 'FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_BOOLEAN_TYPE_INVALID'
    }
    $validatedRoot = Assert-PostRunSupervisorTrustRoot $TrustRootEvidence `
        $ExpectedTrustRootSha256 $ApprovedTrustRootSha256 -AllowTestFixture:$AllowTestFixture
    if ([bool]$receipt.test_fixture) {
        if (-not $AllowTestFixture -or
                $receipt.artifact_class -cne 'TEST_FEDERATION_POSTRUN_RECEIPT_FIXTURE' -or
                $receipt.source_mode -cne 'TEST_SIGNED_PARSER_FIXTURE' -or
                -not [bool]$validatedRoot.value.test_fixture) {
            throw 'FABRIC_FEDERATION_GUI_TEST_POSTRUN_RECEIPT_RELEASE_REJECTED'
        }
    } elseif ($receipt.artifact_class -cne $postRunReceiptArtifactClass -or
            $receipt.source_mode -cne 'EXTERNAL_POSTRUN_SUPERVISOR') {
        throw 'FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_PROVENANCE_INVALID'
    }
    if ($receipt.schema -cne $postRunReceiptSchema -or
            $receipt.signer_key_id -cne [string]$validatedRoot.value.key_id -or
            $receipt.signer_trust_root_sha256 -cne $ExpectedTrustRootSha256.ToLowerInvariant() -or
            $receipt.signature_algorithm -cne 'RSA_PKCS1_SHA256') {
        throw 'FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_SIGNER_BINDING_INVALID'
    }
    foreach ($name in @('release_bundle_manifest_sha256','release_bundle_fabric_jar_sha256',
            'release_bundle_paper_jar_sha256','release_bundle_source_proxy_jar_sha256',
            'release_bundle_target_proxy_jar_sha256','supervisor_process_incarnation_id',
            'source_proxy_process_incarnation_id','target_proxy_process_incarnation_id',
            'source_paper_process_incarnation_id','target_paper_process_incarnation_id',
            'fabric_client_process_incarnation_id','visible_gui_attestation_sha256',
            'visible_gui_screenshot_sha256','visible_gui_screenshot_decoded_pixel_sha256',
            'runtime_ledger_sha256','runtime_ledger_head_sha256',
            'runtime_ledger_supervisor_seal_sha256','report_sha256','binding_sha256')) {
        if (-not (Test-Sha256 $receipt.$name)) {
            throw "FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_HASH_INVALID: $name"
        }
    }
    if ($receipt.release_source_commit -cnotmatch '^[0-9a-f]{40}$' -or
            $receipt.artifact_source_commit -cnotmatch '^[0-9a-f]{40}$' -or
            $receipt.product_version -cne '0.0.1' -or
            $receipt.fabric_target -notin @('1.21.11','26.1.2','26.2') -or
            $receipt.source_proxy -notin @('VELOCITY','BUNGEE') -or
            $receipt.target_proxy -notin @('VELOCITY','BUNGEE') -or
            $receipt.run_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            $receipt.gui_challenge_nonce -cnotmatch '^[0-9a-f]{64}$' -or
            $receipt.postrun_operation_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            $receipt.postrun_challenge_nonce -cnotmatch '^[0-9a-f]{64}$' -or
            [long]$receipt.runtime_ledger_size_bytes -lt 256 -or
            [int]$receipt.runtime_ledger_event_count -ne 18 -or
            [long]$receipt.report_size_bytes -le 0 -or [long]$receipt.binding_size_bytes -le 0) {
        throw 'FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_VALUE_INVALID'
    }
    foreach ($entry in $Expected.GetEnumerator()) {
        $actual = $receipt.PSObject.Properties[[string]$entry.Key].Value
        if ($entry.Value -is [byte] -or $entry.Value -is [int16] -or
                $entry.Value -is [int32] -or $entry.Value -is [int64]) {
            if (-not (Test-JsonInteger $actual) -or [long]$actual -ne [long]$entry.Value) {
                throw "FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_BINDING_INVALID: $($entry.Key)"
            }
        } elseif (-not (Test-JsonString $actual) -or
                [string]$actual -cne [string]$entry.Value) {
            throw "FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_BINDING_INVALID: $($entry.Key)"
        }
    }
    $signedAt = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact([string]$receipt.signed_at, 'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None, [ref]$signedAt) -or
            $signedAt.ToUniversalTime().Ticks -lt $ChallengeIssuedAt.ToUniversalTime().Ticks -or
            $signedAt.ToUniversalTime().Ticks -gt [DateTimeOffset]::UtcNow.AddMinutes(1).Ticks -or
            ($signedAt.ToUniversalTime() - $ChallengeIssuedAt.ToUniversalTime()).TotalMinutes -gt 5) {
        throw 'FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_TIME_INVALID'
    }
    try { $signature = [Convert]::FromBase64String([string]$receipt.signature_base64) }
    catch { throw 'FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_SIGNATURE_ENCODING_INVALID' }
    if ($signature.Length -ne $validatedRoot.modulus.Length -or
            -not (Test-RsaPkcs1Sha256Signature `
                (Get-PostRunReceiptSigningPayload $receipt) $signature `
                $validatedRoot.modulus $validatedRoot.exponent)) {
        throw 'FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_SIGNATURE_INVALID'
    }
    return [pscustomobject]@{ value=$receipt; signed_at=$signedAt.ToUniversalTime().ToString('o') }
}

function Get-PostRunReceiptExpectedBinding(
        [object]$ReleaseBinding,
        [object]$Report,
        [object]$ReportEvidence,
        [object]$BindingEvidence,
        [object]$AttestationEvidence,
        [object]$ScreenshotEvidence,
        [object]$ValidatedAttestation,
        [object]$LedgerEvidence,
        [object]$ValidatedLedger,
        [string]$PostRunOperationAttemptId,
        [string]$PostRunChallengeNonce,
        [string]$PostRunChallengeIssuedAt) {
    return [ordered]@{
        release_source_commit = [string]$ReleaseBinding.bundle_source_commit
        artifact_source_commit = [string]$ReleaseBinding.artifact_source_commit
        product_version = [string]$ReleaseBinding.product_version
        fabric_target = [string]$Report.fabric_target
        source_proxy = [string]$Report.source_proxy
        target_proxy = [string]$Report.target_proxy
        release_bundle_manifest_sha256 = [string]$ReleaseBinding.manifest_sha256
        release_bundle_fabric_jar_sha256 = [string]$ReleaseBinding.fabric_jar_sha256
        release_bundle_paper_jar_sha256 = [string]$ReleaseBinding.paper_jar_sha256
        release_bundle_source_proxy_jar_sha256 = [string]$ReleaseBinding.source_proxy_jar_sha256
        release_bundle_target_proxy_jar_sha256 = [string]$ReleaseBinding.target_proxy_jar_sha256
        run_attempt_id = [string]$Report.run_attempt_id
        gui_challenge_nonce = [string]$Report.gui_challenge_nonce
        postrun_operation_attempt_id = $PostRunOperationAttemptId
        postrun_challenge_nonce = $PostRunChallengeNonce
        postrun_challenge_issued_at = $PostRunChallengeIssuedAt
        supervisor_process_incarnation_id = [string]$ValidatedLedger.supervisor_process_incarnation_id
        source_proxy_process_incarnation_id = [string]$ValidatedLedger.source_proxy_process_incarnation_id
        target_proxy_process_incarnation_id = [string]$ValidatedLedger.target_proxy_process_incarnation_id
        source_paper_process_incarnation_id = [string]$ValidatedLedger.source_paper_process_incarnation_id
        target_paper_process_incarnation_id = [string]$ValidatedLedger.target_paper_process_incarnation_id
        fabric_client_process_incarnation_id = [string]$ValidatedLedger.fabric_client_process_incarnation_id
        visible_gui_attestation_sha256 = [string]$AttestationEvidence.sha256
        visible_gui_screenshot_sha256 = [string]$ScreenshotEvidence.sha256
        visible_gui_screenshot_decoded_pixel_sha256 = [string]$ValidatedAttestation.screenshot_decoded_pixel_sha256
        runtime_ledger_sha256 = [string]$LedgerEvidence.sha256
        runtime_ledger_size_bytes = [long]$LedgerEvidence.size_bytes
        runtime_ledger_head_sha256 = [string]$ValidatedLedger.head_sha256
        runtime_ledger_supervisor_seal_sha256 = [string]$ValidatedLedger.supervisor_seal_sha256
        runtime_ledger_event_count = [int]$ValidatedLedger.event_count
        report_sha256 = [string]$ReportEvidence.sha256
        report_size_bytes = [long]$ReportEvidence.size_bytes
        binding_sha256 = [string]$BindingEvidence.sha256
        binding_size_bytes = [long]$BindingEvidence.size_bytes
    }
}

function Test-JsonString([object]$Value) { return $Value -is [string] }
function Test-JsonBoolean([object]$Value) { return $Value -is [bool] }
function Test-Sha256([object]$Value) {
    return $Value -is [string] -and [string]$Value -cmatch '^[0-9a-f]{64}$'
}

function New-CryptographicHex([int]$ByteCount) {
    if ($ByteCount -lt 16 -or $ByteCount -gt 64) { throw 'FABRIC_FEDERATION_GUI_RANDOM_SIZE_INVALID' }
    $bytes = New-Object byte[] $ByteCount
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

function Read-StrictPropertiesBytes([byte[]]$Bytes, [string]$Role) {
    try { $raw = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes) }
    catch { throw "FABRIC_FEDERATION_GUI_${Role}_UTF8_INVALID" }
    $result = [ordered]@{}
    foreach ($line in @($raw -split '\r?\n')) {
        $text = ([string]$line).Trim()
        if ($text.Length -eq 0 -or $text.StartsWith('#') -or $text.StartsWith('!')) { continue }
        $separator = $text.IndexOf('=')
        if ($separator -lt 1) { throw "FABRIC_FEDERATION_GUI_${Role}_LINE_INVALID" }
        $key = $text.Substring(0, $separator).Trim()
        $value = $text.Substring($separator + 1).Trim()
        if ($key -cnotmatch '^[A-Za-z0-9._-]+$' -or $result.Contains($key)) {
            throw "FABRIC_FEDERATION_GUI_${Role}_KEY_INVALID"
        }
        $result[$key] = $value
    }
    return $result
}

function Get-ReleaseBundleTargetBinding(
        [string]$Root,
        [string]$ExpectedBundleSourceCommit,
        [string]$ExpectedArtifactSourceCommit,
        [string]$Target,
        [string]$ExpectedSourceProxy,
        [string]$ExpectedTargetProxy) {
    $resolvedRoot = Assert-DirectLocalPath $Root -Directory
    $expectedNames = @('SHA256SUMS','release-manifest.properties',
        'mcace-client-fabric-1.21.11.jar','mcace-client-fabric-26.1.2.jar',
        'mcace-client-fabric-26.2.jar','mcace-server-velocity.jar',
        'mcace-server-bungeecord.jar','mcace-server-paper.jar')
    $entries = @(Get-ChildItem -LiteralPath $resolvedRoot -Force -ErrorAction Stop)
    if ($entries.Count -ne 8 -or
            ((@($entries.Name | Sort-Object) -join '|') -cne (($expectedNames | Sort-Object) -join '|'))) {
        throw 'FABRIC_FEDERATION_GUI_RELEASE_BUNDLE_FILE_SET_INVALID'
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'FABRIC_FEDERATION_GUI_RELEASE_BUNDLE_ENTRY_TYPE_INVALID'
        }
    }
    $manifestDoc = Open-LockedFileBytes (Join-Path $resolvedRoot 'release-manifest.properties') 64 1048576 'RELEASE_MANIFEST'
    $sumsDoc = $null
    $artifactDocs = @{}
    try {
        $manifest = Read-StrictPropertiesBytes $manifestDoc.bytes 'RELEASE_MANIFEST'
        if ($manifest['schema'] -cne 'MCACE_RELEASE_BUNDLE_V4' -or
                $manifest['bundle_profile'] -cne 'RELEASE' -or
                $manifest['release_identity'] -cne 'true' -or
                $manifest['product_version'] -cne '0.0.1' -or
                $manifest['source_commit'] -cne $ExpectedBundleSourceCommit -or
                $manifest['artifact_source_commit'] -cne $ExpectedArtifactSourceCommit -or
                $manifest['deployable_count'] -cne '6' -or $manifest['bundle_entry_count'] -cne '8') {
            throw 'FABRIC_FEDERATION_GUI_RELEASE_BUNDLE_MANIFEST_INVALID'
        }
        $jarName = "mcace-client-fabric-$Target.jar"
        $key = $jarName.Remove($jarName.Length - 4).Replace('-', '_').Replace('.', '_')
        $manifestShaKey = "artifact.$key.sha256"
        $manifestFileKey = "artifact.$key.file"
        $manifestTargetKey = "artifact.$key.minecraft_version"
        $manifestBuildKey = "artifact.$key.client_build_id"
        $expectedBuildId = "fabric-$Target-$ExpectedArtifactSourceCommit"
        if ($manifest[$manifestFileKey] -cne $jarName -or
                $manifest[$manifestTargetKey] -cne $Target -or
                $manifest[$manifestBuildKey] -cne $expectedBuildId -or
                -not (Test-Sha256 $manifest[$manifestShaKey])) {
            throw 'FABRIC_FEDERATION_GUI_RELEASE_BUNDLE_TARGET_IDENTITY_INVALID'
        }
        $sumsDoc = Open-LockedFileBytes (Join-Path $resolvedRoot 'SHA256SUMS') 64 1048576 'RELEASE_SHA256SUMS'
        try { $sumsRaw = [Text.UTF8Encoding]::new($false, $true).GetString($sumsDoc.bytes) }
        catch { throw 'FABRIC_FEDERATION_GUI_RELEASE_SHA256SUMS_UTF8_INVALID' }
        if ($sumsRaw.Contains("`r") -or -not $sumsRaw.EndsWith("`n")) {
            throw 'FABRIC_FEDERATION_GUI_RELEASE_SHA256SUMS_CANONICAL_ENCODING_INVALID'
        }
        $sumEntries = @($sumsRaw.TrimEnd("`n") -split "`n")
        $expectedJarNames = @('mcace-client-fabric-1.21.11.jar','mcace-client-fabric-26.1.2.jar',
            'mcace-client-fabric-26.2.jar','mcace-server-velocity.jar',
            'mcace-server-bungeecord.jar','mcace-server-paper.jar')
        if ($sumEntries.Count -ne 6) { throw 'FABRIC_FEDERATION_GUI_RELEASE_SHA256SUMS_SET_INVALID' }
        $seenSums = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $sumMap = @{}
        foreach ($line in $sumEntries) {
            if ($line -cnotmatch '^(?<sha>[0-9a-f]{64})  (?<file>[A-Za-z0-9][A-Za-z0-9._-]*\.jar)$' -or
                    $Matches.file -cnotin $expectedJarNames -or -not $seenSums.Add($Matches.file)) {
                throw 'FABRIC_FEDERATION_GUI_RELEASE_SHA256SUMS_SET_INVALID'
            }
            $sumMap[[string]$Matches.file] = [string]$Matches.sha
        }
        $sourceProxyJar = if ($ExpectedSourceProxy -ceq 'VELOCITY') {
            'mcace-server-velocity.jar'
        } elseif ($ExpectedSourceProxy -ceq 'BUNGEE') {
            'mcace-server-bungeecord.jar'
        } else { throw 'FABRIC_FEDERATION_GUI_RELEASE_SOURCE_PROXY_INVALID' }
        $targetProxyJar = if ($ExpectedTargetProxy -ceq 'VELOCITY') {
            'mcace-server-velocity.jar'
        } elseif ($ExpectedTargetProxy -ceq 'BUNGEE') {
            'mcace-server-bungeecord.jar'
        } else { throw 'FABRIC_FEDERATION_GUI_RELEASE_TARGET_PROXY_INVALID' }
        $requiredRuntimeArtifacts = @($jarName, 'mcace-server-paper.jar',
            $sourceProxyJar, $targetProxyJar) | Select-Object -Unique
        foreach ($artifactName in $requiredRuntimeArtifacts) {
            $artifactKey = $artifactName.Remove($artifactName.Length - 4).Replace('-', '_').Replace('.', '_')
            $artifactManifestFileKey = "artifact.$artifactKey.file"
            $artifactManifestShaKey = "artifact.$artifactKey.sha256"
            if ($manifest[$artifactManifestFileKey] -cne $artifactName -or
                    -not (Test-Sha256 $manifest[$artifactManifestShaKey]) -or
                    -not $sumMap.ContainsKey($artifactName) -or
                    [string]$sumMap[$artifactName] -cne [string]$manifest[$artifactManifestShaKey]) {
                throw 'FABRIC_FEDERATION_GUI_RELEASE_RUNTIME_ARTIFACT_MANIFEST_INVALID'
            }
            $artifactDoc = Open-LockedFileBytes `
                (Join-Path $resolvedRoot $artifactName) 1024 134217728 'RELEASE_RUNTIME_JAR'
            if ([string]$artifactDoc.sha256 -cne [string]$manifest[$artifactManifestShaKey]) {
                $artifactDoc.stream.Dispose()
                throw 'FABRIC_FEDERATION_GUI_RELEASE_RUNTIME_ARTIFACT_HASH_INVALID'
            }
            $artifactDocs[$artifactName] = $artifactDoc
        }
        $fabricDoc = $artifactDocs[$jarName]
        $paperDoc = $artifactDocs['mcace-server-paper.jar']
        $sourceProxyDoc = $artifactDocs[$sourceProxyJar]
        $targetProxyDoc = $artifactDocs[$targetProxyJar]
        return [pscustomobject]@{
            root=$resolvedRoot; manifest_sha256=$manifestDoc.sha256
            product_version=[string]$manifest['product_version']
            fabric_jar_file=$jarName; fabric_jar_sha256=$fabricDoc.sha256
            fabric_jar_size_bytes=$fabricDoc.size_bytes; client_build_id=$expectedBuildId
            paper_jar_file='mcace-server-paper.jar'; paper_jar_sha256=$paperDoc.sha256
            source_proxy_jar_file=$sourceProxyJar; source_proxy_jar_sha256=$sourceProxyDoc.sha256
            target_proxy_jar_file=$targetProxyJar; target_proxy_jar_sha256=$targetProxyDoc.sha256
            bundle_source_commit=[string]$manifest['source_commit']
            artifact_source_commit=[string]$manifest['artifact_source_commit']
        }
    } finally {
        if ($null -ne $sumsDoc) { $sumsDoc.stream.Dispose() }
        foreach ($artifactDoc in @($artifactDocs.Values)) {
            if ($null -ne $artifactDoc) { $artifactDoc.stream.Dispose() }
        }
        $manifestDoc.stream.Dispose()
    }
}

$runtimeEventPropertyNames = @(
    'schema','sequence','observed_at','event_type','run_attempt_id','operation_attempt_id',
    'source_commit','fabric_target','supervisor_process_id','supervisor_process_started_at',
    'actor_role','process_id','process_started_at','process_incarnation_id','peer',
    'connection_id','session_id','subject_commitment_sha256','evidence_marker_sha256',
    'previous_event_sha256','supervisor_seal_sha256','event_sha256'
)

function Get-ProcessStartTimeString([Diagnostics.Process]$Process) {
    return ([DateTimeOffset]$Process.StartTime.ToUniversalTime()).ToString('o')
}

function Get-ProcessIncarnationId([string]$Role, [int]$ProcessId, [string]$StartedAt) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        "MCACE_PROCESS_INCARNATION_V1`nrole=$Role`npid=$ProcessId`nstarted_at=$StartedAt`n")
    return Get-BytesSha256 $bytes
}

function Get-RuntimeEventSigningPayload([object]$Event) {
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('MCACE_FABRIC_FEDERATION_RUNTIME_EVENT_SIGNING_V1')
    foreach ($name in @($runtimeEventPropertyNames | Where-Object { $_ -cne 'event_sha256' })) {
        $value = $Event.$name
        if ($value -is [byte] -or $value -is [sbyte] -or $value -is [int16] -or
                $value -is [uint16] -or $value -is [int32] -or $value -is [uint32] -or
                $value -is [int64] -or $value -is [uint64]) {
            $rendered = [Convert]::ToString($value, [Globalization.CultureInfo]::InvariantCulture)
        } else { $rendered = [string]$value }
        if ($rendered -match '[\r\n]') { throw 'FABRIC_FEDERATION_GUI_RUNTIME_EVENT_VALUE_INVALID' }
        $lines.Add("$name=$rendered")
    }
    return [Text.UTF8Encoding]::new($false).GetBytes(($lines -join "`n") + "`n")
}

function New-RuntimeLedger(
        [string]$Path,
        [string]$RunAttemptId,
        [string]$SourceCommit,
        [string]$Target) {
    if (Test-Path -LiteralPath $Path) { throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_PREEXISTING' }
    $supervisor = Get-Process -Id $PID -ErrorAction Stop
    $started = Get-ProcessStartTimeString $supervisor
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    $stream.Flush($true); $stream.Dispose()
    return [pscustomobject]@{
        path=$Path; run_attempt_id=$RunAttemptId; source_commit=$SourceCommit; fabric_target=$Target
        sequence=0; previous_event_sha256=('0' * 64); expected_length=0L
        supervisor_process_id=[int]$PID; supervisor_process_started_at=$started
        supervisor_incarnation_id=Get-ProcessIncarnationId 'SUPERVISOR' ([int]$PID) $started
    }
}

function Add-RuntimeLedgerEvent(
        [object]$Ledger,
        [string]$EventType,
        [string]$OperationAttemptId,
        [string]$ActorRole,
        [int]$ProcessId,
        [string]$ProcessStartedAt,
        [string]$Peer,
        [string]$ConnectionId,
        [string]$SessionId,
        [string]$SubjectCommitmentSha256,
        [string]$EvidenceMarkerSha256,
        [string]$SupervisorSealSha256 = '',
        [string]$ObservedAt = '') {
    $incarnation = Get-ProcessIncarnationId $ActorRole $ProcessId $ProcessStartedAt
    $observed = [DateTimeOffset]::UtcNow
    if (-not [string]::IsNullOrWhiteSpace($ObservedAt)) {
        if (-not [DateTimeOffset]::TryParseExact(
                $ObservedAt, 'o', [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::None, [ref]$observed)) {
            throw 'FABRIC_FEDERATION_GUI_RUNTIME_EVENT_OBSERVED_AT_INVALID'
        }
    }
    $event = [ordered]@{
        schema=$runtimeEventSchema; sequence=[int]($Ledger.sequence + 1)
        observed_at=$observed.ToUniversalTime().ToString('o'); event_type=$EventType
        run_attempt_id=[string]$Ledger.run_attempt_id; operation_attempt_id=$OperationAttemptId
        source_commit=[string]$Ledger.source_commit; fabric_target=[string]$Ledger.fabric_target
        supervisor_process_id=[int]$Ledger.supervisor_process_id
        supervisor_process_started_at=[string]$Ledger.supervisor_process_started_at
        actor_role=$ActorRole; process_id=$ProcessId; process_started_at=$ProcessStartedAt
        process_incarnation_id=$incarnation; peer=$Peer; connection_id=$ConnectionId
        session_id=$SessionId; subject_commitment_sha256=$SubjectCommitmentSha256
        evidence_marker_sha256=$EvidenceMarkerSha256
        previous_event_sha256=[string]$Ledger.previous_event_sha256
        supervisor_seal_sha256=$SupervisorSealSha256; event_sha256=''
    }
    $event.event_sha256 = Get-BytesSha256 (Get-RuntimeEventSigningPayload ([pscustomobject]$event))
    $line = [Text.UTF8Encoding]::new($false).GetBytes((([pscustomobject]$event | ConvertTo-Json -Compress) + "`n"))
    $beforeIdentity = Get-NoFollowFileIdentity $Ledger.path
    $stream = [IO.File]::Open($Ledger.path, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        if ($stream.Position -ne [long]$Ledger.expected_length) {
            throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_APPEND_POSITION_INVALID'
        }
        $stream.Write($line, 0, $line.Length); $stream.Flush($true)
    } finally { $stream.Dispose() }
    $afterIdentity = Get-NoFollowFileIdentity $Ledger.path
    if ($beforeIdentity -cne $afterIdentity) { throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_FILE_REPLACED' }
    $Ledger.sequence = [int]$event.sequence
    $Ledger.previous_event_sha256 = [string]$event.event_sha256
    $Ledger.expected_length = [long]$Ledger.expected_length + $line.Length
    return [pscustomobject]$event
}

function Add-ServiceRuntimeEvent(
        [object]$Ledger,
        [string]$EventType,
        [string]$OperationAttemptId,
        [string]$ActorRole,
        [Diagnostics.Process]$Process,
        [string]$Peer,
        [string]$ConnectionId,
        [string]$SessionId,
        [string]$SubjectCommitmentSha256,
        [string]$EvidenceMarker,
        [string]$ObservedAt = '') {
    $started = Get-ProcessStartTimeString $Process
    $markerHash = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($EvidenceMarker))
    return Add-RuntimeLedgerEvent $Ledger $EventType $OperationAttemptId $ActorRole `
        ([int]$Process.Id) $started $Peer $ConnectionId $SessionId `
        $SubjectCommitmentSha256 $markerHash '' $ObservedAt
}

function Complete-RuntimeLedger([object]$Ledger, [string]$ChallengeNonce) {
    $sealPayload = [Text.UTF8Encoding]::new($false).GetBytes(
        "MCACE_FABRIC_FEDERATION_RUNTIME_LEDGER_SEAL_V1`n" +
        "source_commit=$($Ledger.source_commit)`nfabric_target=$($Ledger.fabric_target)`n" +
        "run_attempt_id=$($Ledger.run_attempt_id)`nchallenge_nonce=$ChallengeNonce`n" +
        "event_count=$($Ledger.sequence)`nhead=$($Ledger.previous_event_sha256)`n" +
        "supervisor_process_id=$($Ledger.supervisor_process_id)`n" +
        "supervisor_process_started_at=$($Ledger.supervisor_process_started_at)`n")
    $seal = Get-BytesSha256 $sealPayload
    $null = Add-RuntimeLedgerEvent $Ledger 'SUPERVISOR_SEALED' '' 'SUPERVISOR' `
        ([int]$Ledger.supervisor_process_id) ([string]$Ledger.supervisor_process_started_at) `
        '' '' '' ('0' * 64) (Get-BytesSha256 $sealPayload) $seal
    return $seal
}

function Assert-RuntimeLedgerBytes(
        [byte[]]$Bytes,
        [string]$ExpectedSourceCommit,
        [string]$ExpectedTarget,
        [string]$ExpectedRunAttemptId,
        [string]$ExpectedChallengeNonce) {
    if ($Bytes.Length -lt 256 -or $Bytes.Length -gt 1048576 -or
            $Bytes[$Bytes.Length - 1] -ne 0x0a -or $Bytes -contains 0x0d -or $Bytes -contains 0x00) {
        throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_SIZE_OR_TERMINATOR_INVALID'
    }
    if ($ExpectedSourceCommit -cnotmatch '^[0-9a-f]{40}$' -or
            $ExpectedTarget -notin @('1.21.11','26.1.2','26.2') -or
            $ExpectedRunAttemptId -cnotmatch '^[0-9a-f]{32}$' -or
            $ExpectedChallengeNonce -cnotmatch '^[0-9a-f]{64}$') {
        throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_EXPECTED_BINDING_INVALID'
    }
    try { $raw = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes) }
    catch { throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_UTF8_INVALID' }
    $lines = @($raw.TrimEnd("`n") -split "`n")
    $expectedTypes = @(
        'RUN_STARTED',
        'PROCESS_STARTED','PROCESS_STARTED','PROCESS_STARTED','PROCESS_STARTED','PROCESS_STARTED',
        # The client must receive and approve the connection-level policy before it can
        # send the first authenticated hello.  Keep the ledger in the same order as
        # that real protocol transition; SOURCE_CONNECTION_VERIFIED is emitted only
        # after the accepted consent has produced a verified session/admission.
        'GUI_PROMPT_RENDERED','GUI_SIGNED_RECEIPT_VERIFIED','GUI_ACCEPTED','SOURCE_CONNECTION_VERIFIED',
        'SOURCE_SECOND_EXPORT_REQUESTED','SOURCE_SECOND_EXPORT_REJECTED',
        'SOURCE_SECOND_EXPORT_NO_GRANT_CONFIRMED','TARGET_CONNECTION_VERIFIED',
        'TARGET_INHERITED_EXPORT_REQUESTED','TARGET_INHERITED_EXPORT_REJECTED',
        'TARGET_INHERITED_EXPORT_NO_GRANT_CONFIRMED','SUPERVISOR_SEALED')
    $expectedActors = @(
        'SUPERVISOR','SOURCE_PROXY','TARGET_PROXY','SOURCE_PAPER','TARGET_PAPER','FABRIC_CLIENT',
        'FABRIC_CLIENT','SUPERVISOR','FABRIC_CLIENT','FABRIC_CLIENT',
        'SOURCE_PROXY','FABRIC_CLIENT','SOURCE_PROXY','FABRIC_CLIENT',
        'TARGET_PROXY','FABRIC_CLIENT','TARGET_PROXY','SUPERVISOR')
    if ($lines.Count -ne $expectedTypes.Count) {
        throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_EVENT_SET_INVALID'
    }
    $events = [Collections.Generic.List[object]]::new()
    $previous = '0' * 64; $supervisorPid = 0; $supervisorStarted = ''
    $previousObserved = [DateTimeOffset]::MinValue
    $roleIncarnations = @{}
    $stringProperties = @('schema','observed_at','event_type','run_attempt_id',
        'operation_attempt_id','source_commit','fabric_target','supervisor_process_started_at',
        'actor_role','process_started_at','process_incarnation_id','peer','connection_id','session_id',
        'subject_commitment_sha256','evidence_marker_sha256','previous_event_sha256',
        'supervisor_seal_sha256','event_sha256')
    for ($index = 0; $index -lt $lines.Count; $index++) {
        $event = ConvertFrom-StrictJson ([string]$lines[$index])
        foreach ($name in $stringProperties) {
            if (-not (Test-JsonString $event.$name)) {
                throw "FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_EVENT_TYPE_INVALID: $($index + 1)/$name"
            }
        }
        if (-not (Test-ExactJsonProperties $event $runtimeEventPropertyNames) -or
                $event.schema -cne $runtimeEventSchema -or
                -not (Test-JsonInteger $event.sequence) -or [int]$event.sequence -ne $index + 1 -or
                -not (Test-JsonInteger $event.supervisor_process_id) -or
                -not (Test-JsonInteger $event.process_id) -or
                [int]$event.supervisor_process_id -le 0 -or [int]$event.process_id -le 0 -or
                $event.source_commit -cne $ExpectedSourceCommit -or
                $event.fabric_target -cne $ExpectedTarget -or
                $event.run_attempt_id -cne $ExpectedRunAttemptId -or
                $event.event_type -cne $expectedTypes[$index] -or
                $event.actor_role -cne $expectedActors[$index] -or
                ([string]$event.operation_attempt_id -ne '' -and
                    [string]$event.operation_attempt_id -cnotmatch '^[0-9a-f]{32}$') -or
                ([string]$event.connection_id -ne '' -and
                    [string]$event.connection_id -cnotmatch '^[0-9a-f]{32}$') -or
                ([string]$event.session_id -ne '' -and
                    [string]$event.session_id -cnotmatch '^[0-9a-f]{32}$') -or
                ([string]$event.peer -ne '' -and
                    [string]$event.peer -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$') -or
                $event.previous_event_sha256 -cne $previous -or
                -not (Test-Sha256 $event.process_incarnation_id) -or
                -not (Test-Sha256 $event.subject_commitment_sha256) -or
                -not (Test-Sha256 $event.evidence_marker_sha256) -or
                -not (Test-Sha256 $event.event_sha256) -or
                (Get-BytesSha256 (Get-RuntimeEventSigningPayload $event)) -cne $event.event_sha256) {
            throw "FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_EVENT_INVALID: $($index + 1)"
        }
        $observed = [DateTimeOffset]::MinValue
        $processStarted = [DateTimeOffset]::MinValue
        $supervisorEventStarted = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParseExact([string]$event.observed_at, 'o',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::None, [ref]$observed) -or
                -not [DateTimeOffset]::TryParseExact([string]$event.process_started_at, 'o',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::None, [ref]$processStarted) -or
                -not [DateTimeOffset]::TryParseExact([string]$event.supervisor_process_started_at, 'o',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::None, [ref]$supervisorEventStarted) -or
                $observed.ToUniversalTime().Ticks -lt $previousObserved.ToUniversalTime().Ticks -or
                $processStarted.ToUniversalTime().Ticks -gt $observed.ToUniversalTime().Ticks -or
                $supervisorEventStarted.ToUniversalTime().Ticks -gt $observed.ToUniversalTime().Ticks) {
            throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_EVENT_TIME_INVALID'
        }
        $previousObserved = $observed
        $computedIncarnation = Get-ProcessIncarnationId ([string]$event.actor_role) `
            ([int]$event.process_id) ([string]$event.process_started_at)
        if ($computedIncarnation -cne [string]$event.process_incarnation_id) {
            throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_PROCESS_INCARCERATION_INVALID'
        }
        $role = [string]$event.actor_role
        $roleIdentity = "$($event.process_id)|$($event.process_started_at)|$($event.process_incarnation_id)"
        if ($roleIncarnations.ContainsKey($role)) {
            if ([string]$roleIncarnations[$role] -cne $roleIdentity) {
                throw "FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_ROLE_INCARCERATION_CHANGED: $role"
            }
        } else { $roleIncarnations[$role] = $roleIdentity }
        if ($index -eq 0) { $supervisorPid=[int]$event.supervisor_process_id; $supervisorStarted=[string]$event.supervisor_process_started_at }
        elseif ([int]$event.supervisor_process_id -ne $supervisorPid -or
                [string]$event.supervisor_process_started_at -cne $supervisorStarted) {
            throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_SUPERVISOR_INCARCERATION_CHANGED'
        }
        if (($index -lt $lines.Count - 1 -and [string]$event.supervisor_seal_sha256 -ne '') -or
                ($index -eq $lines.Count - 1 -and -not (Test-Sha256 $event.supervisor_seal_sha256))) {
            throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_PREMATURE_OR_MISSING_SEAL'
        }
        $previous = [string]$event.event_sha256
        $events.Add($event)
    }
    if ($events[$events.Count - 1].event_type -cne 'SUPERVISOR_SEALED') {
        throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_SEAL_EVENT_MISSING'
    }
    $sealEvent = $events[$events.Count - 1]
    $preSealHead = [string]$sealEvent.previous_event_sha256
    $sealPayload = [Text.UTF8Encoding]::new($false).GetBytes(
        "MCACE_FABRIC_FEDERATION_RUNTIME_LEDGER_SEAL_V1`n" +
        "source_commit=$ExpectedSourceCommit`nfabric_target=$ExpectedTarget`n" +
        "run_attempt_id=$ExpectedRunAttemptId`nchallenge_nonce=$ExpectedChallengeNonce`n" +
        "event_count=$($events.Count - 1)`nhead=$preSealHead`n" +
        "supervisor_process_id=$supervisorPid`n" +
        "supervisor_process_started_at=$supervisorStarted`n")
    $expectedSeal = Get-BytesSha256 $sealPayload
    if ($sealEvent.supervisor_seal_sha256 -cne $expectedSeal -or
            $sealEvent.evidence_marker_sha256 -cne $expectedSeal -or
            $sealEvent.actor_role -cne 'SUPERVISOR' -or
            [int]$sealEvent.process_id -ne $supervisorPid -or
            $sealEvent.process_started_at -cne $supervisorStarted -or
            $sealEvent.operation_attempt_id -cne '' -or $sealEvent.peer -cne '' -or
            $sealEvent.connection_id -cne '' -or $sealEvent.session_id -cne '' -or
            $sealEvent.subject_commitment_sha256 -cne ('0' * 64)) {
        throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_SUPERVISOR_SEAL_INVALID'
    }
    function Assert-NegativeCorrelation([string]$Prefix) {
        $request = @($events | Where-Object event_type -CEQ "${Prefix}_REQUESTED")
        $rejected = @($events | Where-Object event_type -CEQ "${Prefix}_REJECTED")
        $noGrant = @($events | Where-Object event_type -CEQ "${Prefix}_NO_GRANT_CONFIRMED")
        if ($request.Count -ne 1 -or $rejected.Count -ne 1 -or $noGrant.Count -ne 1) {
            throw "FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_NEGATIVE_EVENT_SET_INVALID: $Prefix"
        }
        foreach ($name in @('operation_attempt_id','peer','connection_id','session_id','subject_commitment_sha256')) {
            $value = [string]$request[0].$name
            if ([string]::IsNullOrWhiteSpace($value) -or [string]$rejected[0].$name -cne $value -or
                    [string]$noGrant[0].$name -cne $value) {
                throw "FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_NEGATIVE_CORRELATION_INVALID: $Prefix/$name"
            }
        }
    }
    Assert-NegativeCorrelation 'SOURCE_SECOND_EXPORT'
    Assert-NegativeCorrelation 'TARGET_INHERITED_EXPORT'
    $sourceNegative = @($events | Where-Object event_type -CEQ 'SOURCE_SECOND_EXPORT_REQUESTED')[0]
    $targetNegative = @($events | Where-Object event_type -CEQ 'TARGET_INHERITED_EXPORT_REQUESTED')[0]
    if ($sourceNegative.operation_attempt_id -ceq $targetNegative.operation_attempt_id -or
            $sourceNegative.peer -ceq $targetNegative.peer -or
            $sourceNegative.connection_id -ceq $targetNegative.connection_id -or
            $sourceNegative.session_id -cne $targetNegative.session_id -or
            $sourceNegative.subject_commitment_sha256 -cne $targetNegative.subject_commitment_sha256) {
        throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_NEGATIVE_ATTEMPT_ALIAS_REJECTED'
    }
    $runStarted = $events[0]
    $sourceConnection = @($events | Where-Object event_type -CEQ 'SOURCE_CONNECTION_VERIFIED')[0]
    $guiPrompt = @($events | Where-Object event_type -CEQ 'GUI_PROMPT_RENDERED')[0]
    $guiReceipt = @($events | Where-Object event_type -CEQ 'GUI_SIGNED_RECEIPT_VERIFIED')[0]
    $guiAccepted = @($events | Where-Object event_type -CEQ 'GUI_ACCEPTED')[0]
    $targetConnection = @($events | Where-Object event_type -CEQ 'TARGET_CONNECTION_VERIFIED')[0]
    $sourceProxyProcess = @($events | Where-Object {
        $_.event_type -CEQ 'PROCESS_STARTED' -and $_.actor_role -CEQ 'SOURCE_PROXY' })[0]
    $targetProxyProcess = @($events | Where-Object {
        $_.event_type -CEQ 'PROCESS_STARTED' -and $_.actor_role -CEQ 'TARGET_PROXY' })[0]
    $sourcePaperProcess = @($events | Where-Object {
        $_.event_type -CEQ 'PROCESS_STARTED' -and $_.actor_role -CEQ 'SOURCE_PAPER' })[0]
    $targetPaperProcess = @($events | Where-Object {
        $_.event_type -CEQ 'PROCESS_STARTED' -and $_.actor_role -CEQ 'TARGET_PAPER' })[0]
    $fabricClientProcess = @($events | Where-Object {
        $_.event_type -CEQ 'PROCESS_STARTED' -and $_.actor_role -CEQ 'FABRIC_CLIENT' })[0]
    $expectedRunMarker = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes(
        "run-attempt=$ExpectedRunAttemptId;challenge=$ExpectedChallengeNonce"))
    foreach ($event in @($sourceConnection,$guiPrompt,$guiReceipt,$guiAccepted)) {
        if ($event.connection_id -cne $sourceNegative.connection_id -or
                $event.session_id -cne $sourceNegative.session_id -or
                $event.subject_commitment_sha256 -cne $sourceNegative.subject_commitment_sha256) {
            throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_SOURCE_SESSION_BINDING_INVALID'
        }
    }
    if ($targetConnection.connection_id -cne $targetNegative.connection_id -or
            $targetConnection.session_id -cne $targetNegative.session_id -or
            $targetConnection.subject_commitment_sha256 -cne $targetNegative.subject_commitment_sha256 -or
            $runStarted.evidence_marker_sha256 -cne $expectedRunMarker -or
            $runStarted.operation_attempt_id -cne '' -or $runStarted.peer -cne '' -or
            $runStarted.connection_id -cne '' -or $runStarted.session_id -cne '' -or
            $runStarted.subject_commitment_sha256 -cne ('0' * 64)) {
        throw 'FABRIC_FEDERATION_GUI_RUNTIME_LEDGER_CHALLENGE_OR_TARGET_SESSION_BINDING_INVALID'
    }
    return [pscustomobject]@{
        event_count=[int]$events.Count; head_sha256=[string]$sealEvent.event_sha256
        supervisor_seal_sha256=$expectedSeal
        gui_receipt_attestation_sha256=[string]$guiReceipt.evidence_marker_sha256
        supervisor_process_incarnation_id=[string]$runStarted.process_incarnation_id
        source_proxy_process_incarnation_id=[string]$sourceProxyProcess.process_incarnation_id
        target_proxy_process_incarnation_id=[string]$targetProxyProcess.process_incarnation_id
        source_paper_process_incarnation_id=[string]$sourcePaperProcess.process_incarnation_id
        target_paper_process_incarnation_id=[string]$targetPaperProcess.process_incarnation_id
        fabric_client_process_incarnation_id=[string]$fabricClientProcess.process_incarnation_id
        source_negative_attempt_id=[string]$sourceNegative.operation_attempt_id
        source_negative_peer=[string]$sourceNegative.peer
        source_negative_connection_id=[string]$sourceNegative.connection_id
        source_negative_session_id=[string]$sourceNegative.session_id
        source_negative_subject_commitment_sha256=[string]$sourceNegative.subject_commitment_sha256
        target_negative_attempt_id=[string]$targetNegative.operation_attempt_id
        target_negative_peer=[string]$targetNegative.peer
        target_negative_connection_id=[string]$targetNegative.connection_id
        target_negative_session_id=[string]$targetNegative.session_id
        target_negative_subject_commitment_sha256=[string]$targetNegative.subject_commitment_sha256
    }
}

function Resolve-FederationServerAssets {
    $platformAssets = Resolve-ServerMatrixAssets
    $manifestPath = Assert-DirectLocalPath $serverMatrixManifest
    try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'FABRIC_FEDERATION_GUI_SERVER_MATRIX_MANIFEST_INVALID' }
    if ($manifest.schema -cne 'MCACE_SERVER_VERSION_MATRIX_ASSETS_V1' -or
            @($manifest.assets).Count -ne 8) {
        throw 'FABRIC_FEDERATION_GUI_SERVER_MATRIX_MANIFEST_INVALID'
    }
    $bungee = @($manifest.assets | Where-Object {
        $_.project -ceq 'bungeecord' -and $_.version -ceq '2085' -and $_.build -ceq '2085'
    })
    if ($bungee.Count -ne 1 -or
            [string]$bungee[0].url -cne 'https://hub.spigotmc.org/jenkins/job/BungeeCord/2085/artifact/bootstrap/target/BungeeCord.jar' -or
            [string]$bungee[0].sha256 -cne 'e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce' -or
            [long]$bungee[0].size -ne 25599274L -or [string]$bungee[0].channel -cne 'REVIEWED' -or
            [int]$bungee[0].java_major -ne 21 -or
            ((@($bungee[0].target_versions) -join ',') -cne '1.21.11,26.1.2,26.2')) {
        throw 'FABRIC_FEDERATION_GUI_REVIEWED_BUNGEE_IDENTITY_INVALID'
    }
    return [pscustomobject]@{
        manifest_path = $platformAssets.manifest_path
        manifest_sha256 = $platformAssets.manifest_sha256
        velocity = $platformAssets.velocity
        paper = $platformAssets.paper
        prepared_root = $platformAssets.prepared_root
        bungee = [ordered]@{
            Name = 'bungeecord-2085.jar'
            Url = [string]$bungee[0].url
            Sha256 = [string]$bungee[0].sha256
            Size = [long]$bungee[0].size
            Path = Join-Path $serverMatrixRoot 'bungeecord\2085\server.jar'
        }
    }
}

function Get-VerifiedBungeeArtifact([System.Collections.IDictionary]$Artifact) {
    if ($Artifact.Url -cne 'https://hub.spigotmc.org/jenkins/job/BungeeCord/2085/artifact/bootstrap/target/BungeeCord.jar' -or
            $Artifact.Sha256 -cne 'e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce' -or
            [long]$Artifact.Size -ne 25599274L) {
        throw 'FABRIC_FEDERATION_GUI_BUNGEE_DECLARATION_INVALID'
    }
    $path = Assert-DirectLocalPath ([string]$Artifact.Path)
    if ((Get-Item -LiteralPath $path).Length -ne [long]$Artifact.Size -or
            (Get-Sha256 $path) -cne [string]$Artifact.Sha256) {
        throw 'FABRIC_FEDERATION_GUI_BUNGEE_CACHE_INVALID'
    }
    return $path
}

function Get-ImmutableInputBinding {
    $currentWrapper = Get-Sha256 (Assert-DirectLocalPath $wrapperPath)
    $currentPlatform = Get-Sha256 (Assert-DirectLocalPath $platformWrapperPath)
    $rootJava = Resolve-RootJava21
    $targetJava = Resolve-TargetJava
    $gradle = Resolve-OfflineGradle961
    $assets = Resolve-FederationServerAssets
    if ([string]$assets.prepared_root -cne $preparedPaperRoot) {
        throw 'FABRIC_FEDERATION_GUI_PREPARED_TARGET_CHANGED'
    }
    $velocityServer = Get-VerifiedArtifact $assets.velocity
    $bungeeServer = Get-VerifiedBungeeArtifact $assets.bungee
    $paperServer = Get-VerifiedArtifact $assets.paper
    $source = Get-SourceManifestBinding
    $prepared = Get-PreparedPaperBinding
    $fabricAssets = Assert-FabricAssetCache $true
    $sourceCommit = (& git -C $repoRoot rev-parse HEAD 2>$null).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $sourceCommit -cnotmatch '^[0-9a-f]{40}$') {
        throw 'FABRIC_FEDERATION_GUI_SOURCE_COMMIT_UNAVAILABLE'
    }
    return [ordered]@{
        source_commit = $sourceCommit
        wrapper_sha256 = $currentWrapper
        wrapper_test_sha256 = Get-Sha256 (Assert-DirectLocalPath $wrapperTestPath)
        platform_wrapper_sha256 = $currentPlatform
        source_manifest_sha256 = $source.sha256
        source_file_count = [int]$source.file_count
        fabric_target = $FabricTarget
        minecraft_version = [string]$fabricDescriptor.minecraft_version
        fabric_api_version = [string]$fabricDescriptor.fabric_api_version
        fabric_artifact_kind = [string]$fabricDescriptor.artifact_kind
        fabric_java_major = [int]$fabricDescriptor.java_major
        fabric_runtime_mode = $fabricRuntimeMode
        server_matrix_manifest_sha256 = [string]$assets.manifest_sha256
        velocity_server_sha256 = Get-Sha256 $velocityServer
        bungee_server_sha256 = Get-Sha256 $bungeeServer
        paper_server_sha256 = Get-Sha256 $paperServer
        paper_prepared_manifest_sha256 = $prepared.manifest_sha256
        paper_prepared_tree_sha256 = $prepared.tree_sha256
        paper_prepared_file_count = [int]$prepared.file_count
        paper_prepared_total_size = [long]$prepared.total_size
        fabric_asset_cache_verified = [bool]$fabricAssets.fabric_asset_cache_verified
        fabric_version_info_sha1 = [string]$fabricAssets.fabric_version_info_sha1
        fabric_version_info_sha256 = [string]$fabricAssets.fabric_version_info_sha256
        fabric_asset_index_id = [string]$fabricAssets.fabric_asset_index_id
        fabric_asset_index_sha1 = [string]$fabricAssets.fabric_asset_index_sha1
        fabric_asset_index_sha256 = [string]$fabricAssets.fabric_asset_index_sha256
        fabric_asset_index_size = [long]$fabricAssets.fabric_asset_index_size
        fabric_asset_object_manifest_sha256 = [string]$fabricAssets.fabric_asset_object_manifest_sha256
        fabric_asset_object_count = [int]$fabricAssets.fabric_asset_object_count
        fabric_asset_object_total_size = [long]$fabricAssets.fabric_asset_object_total_size
        root_java_executable_sha256 = $rootJava.sha256
        root_java_file_version = $rootJava.file_version
        target_java_executable_sha256 = $targetJava.sha256
        target_java_file_version = $targetJava.file_version
        gradle_version = $gradle.version
        gradle_launcher_sha256 = $gradle.launcher_sha256
        gradle_core_sha256 = $gradle.core_sha256
    }
}

function Get-ReleaseFabricArtifactIdentity(
        [string]$Jar,
        [System.Collections.IDictionary]$Descriptor) {
    $resolved = Assert-DirectLocalPath $Jar
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($resolved)
    try {
        $entry = $archive.GetEntry('fabric.mod.json')
        if ($null -eq $entry) { throw 'FABRIC_FEDERATION_GUI_RELEASE_FABRIC_METADATA_REQUIRED' }
        $reader = [System.IO.StreamReader]::new($entry.Open(), [System.Text.Encoding]::UTF8)
        try { $raw = $reader.ReadToEnd() }
        finally { $reader.Dispose() }
    } finally { $archive.Dispose() }
    try { $metadata = $raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'FABRIC_FEDERATION_GUI_RELEASE_FABRIC_METADATA_INVALID' }
    $version = [string]$metadata.version
    $buildId = if ($null -ne $metadata.custom) {
        [string]$metadata.custom.'mcace:client_build_id'
    } else { '' }
    $minecraftDependency = if ($null -ne $metadata.depends) {
        [string]$metadata.depends.minecraft
    } else { '' }
    $fabricApiDependency = if ($null -ne $metadata.depends) {
        [string]$metadata.depends.'fabric-api'
    } else { '' }
    $javaDependency = if ($null -ne $metadata.depends) {
        [string]$metadata.depends.java
    } else { '' }
    if ($version -cne $fabricArtifactVersion -or
            $buildId -cnotmatch ('^fabric-{0}-[0-9a-f]{{40}}$' -f [regex]::Escape($FabricTarget)) -or
            $minecraftDependency -cne [string]$Descriptor.minecraft_version -or
            $fabricApiDependency -cne [string]$Descriptor.fabric_api_version -or
            $javaDependency -cne ('>={0}' -f [int]$Descriptor.java_major)) {
        throw 'FABRIC_FEDERATION_GUI_RELEASE_FABRIC_BUILD_IDENTITY_INVALID'
    }
    return [pscustomobject]@{
        version = $version
        build_id = $buildId
        minecraft_version = $minecraftDependency
        fabric_api_version = $fabricApiDependency
        java_major = [int]$Descriptor.java_major
    }
}

function Get-CurrentBinding {
    $current = Get-ImmutableInputBinding
    foreach ($artifact in @($fabricArtifactJar, $velocityPlugin, $bungeePlugin, $paperPlugin)) {
        $null = Assert-DirectLocalPath $artifact
    }
    $identity = Get-ReleaseFabricArtifactIdentity $fabricArtifactJar $fabricDescriptor
    $current['fabric_artifact_sha256'] = Get-Sha256 $fabricArtifactJar
    $current['fabric_build_id'] = $identity.build_id
    $current['velocity_plugin_sha256'] = Get-Sha256 $velocityPlugin
    $current['bungee_plugin_sha256'] = Get-Sha256 $bungeePlugin
    $current['paper_plugin_sha256'] = Get-Sha256 $paperPlugin
    return $current
}

function Start-FabricReleaseClient(
        [string]$RunDirectory,
        [string]$ServerAddress,
        [bool]$AwaitEvidence,
        [string]$ExpectedArtifactSha256) {
    if ($ExpectedArtifactSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'FABRIC_FEDERATION_GUI_EXPECTED_RELEASE_FABRIC_SHA256_REQUIRED'
    }
    Assert-SmokeRunToken $runToken
    $loomRunDirectory = Get-CompatibleRelativePath `
        ([string]$fabricDescriptor.project_directory) $RunDirectory
    $runTask = if ([int]$fabricDescriptor.java_major -eq 21) {
        ':mcace-client-fabric:runReleaseClient'
    } else { [string]$fabricDescriptor.run_task }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $script:TargetJavaPath
    $startInfo.WorkingDirectory = [string]$fabricDescriptor.gradle_project_directory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $arguments = [Collections.Generic.List[string]]::new()
    foreach ($argument in @(
            $runTokenJvmArgument, '-Xms128m', '-Xmx1024m', '-classpath',
            $script:OfflineGradle.launcher, 'org.gradle.launcher.GradleMain', $runTask,
            "-PmcaceSmokeRunDirectory=$loomRunDirectory",
            "-PmcaceSmokeServerAddress=$ServerAddress",
            '-PmcaceSmokeArtifactMode=true',
            "-PmcaceClientBuildId=$fabricSmokeBuildId",
            "-PmcaceSmokeExpectedArtifactSha256=$ExpectedArtifactSha256",
            "-PmcaceSmokeRuntimeArtifactPath=$fabricArtifactJar",
            "-PmcaceSmokeRunToken=$runToken",
            "-PmcaceSmokeConsentTimeoutSeconds=$([Math]::Min(300, [Math]::Max(30, [int]$HumanTransitionTimeoutSeconds)))",
            '--rerun-tasks', '--offline', '--dependency-verification=strict',
            '--no-build-cache', '--no-configuration-cache', '--no-daemon',
            '--no-parallel', '--max-workers=1')) {
        $arguments.Add($argument)
    }
    if ([int]$fabricDescriptor.java_major -eq 25) {
        $arguments.Add("-PmcaceRootDepsDir=$stagedModernDependencies")
        $arguments.Add("-PmcaceProductVersion=$fabricArtifactVersion")
    }
    if ($AwaitEvidence) { $arguments.Add('-PmcaceSmokeEvidence=true') }
    Set-ProcessArguments $startInfo $arguments.ToArray()
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'Could not start the Fabric exact release artifact client'
    }
    return [pscustomobject]@{
        Name = 'fabric-client'
        Process = $process
        Pid = $process.Id
        WorkingDirectory = $RunDirectory
        RunToken = $runToken
        Stdout = $process.StandardOutput.ReadToEndAsync()
        Stderr = $process.StandardError.ReadToEndAsync()
        ConsolePath = Join-Path $RunDirectory 'fabric-client-console.log'
    }
}

function Assert-BindingUnchanged(
        [System.Collections.IDictionary]$Before,
        [System.Collections.IDictionary]$After,
        [string]$FailureCode) {
    if ($Before.Count -ne $After.Count) { throw $FailureCode }
    foreach ($name in @($Before.Keys)) {
        if (-not $After.Contains($name) -or [string]$Before[$name] -cne [string]$After[$name]) {
            throw "$FailureCode`: $name"
        }
    }
}

function Assert-ReportOnlyExpectedBinding([System.Collections.IDictionary]$Current) {
    $expected = [ordered]@{
        fabric_artifact_sha256 = $ExpectedFabricArtifactSha256.ToLowerInvariant()
        velocity_plugin_sha256 = $ExpectedVelocityPluginSha256.ToLowerInvariant()
        bungee_plugin_sha256 = $ExpectedBungeePluginSha256.ToLowerInvariant()
        paper_plugin_sha256 = $ExpectedPaperPluginSha256.ToLowerInvariant()
        velocity_server_sha256 = $ExpectedVelocityServerSha256.ToLowerInvariant()
        bungee_server_sha256 = $ExpectedBungeeServerSha256.ToLowerInvariant()
        paper_server_sha256 = $ExpectedPaperServerSha256.ToLowerInvariant()
        paper_prepared_manifest_sha256 = $ExpectedPaperPreparedManifestSha256.ToLowerInvariant()
        paper_prepared_tree_sha256 = $ExpectedPaperPreparedTreeSha256.ToLowerInvariant()
        fabric_version_info_sha256 = $ExpectedFabricVersionInfoSha256.ToLowerInvariant()
        fabric_asset_index_sha256 = $ExpectedFabricAssetIndexSha256.ToLowerInvariant()
        fabric_asset_object_manifest_sha256 = $ExpectedFabricAssetObjectManifestSha256.ToLowerInvariant()
    }
    foreach ($entry in $expected.GetEnumerator()) {
        if ([string]$Current[$entry.Key] -cne [string]$entry.Value) {
            throw "FABRIC_FEDERATION_GUI_REPORT_ONLY_EXPECTED_HASH_MISMATCH: $($entry.Key)"
        }
    }
}

$reportPropertyNames = @(
    'schema', 'generated_at', 'source_mode', 'status', 'artifact_class',
    'source_commit','run_attempt_id','gui_attempt_id','gui_challenge_nonce','gui_challenge_issued_at',
    'gui_signing_request_created_at','gui_signing_request_expires_at',
    'fabric_client_started_at','gui_prompt_rendered_at','enablement_consent_accepted_at',
    'fabric_target', 'minecraft_version', 'fabric_api_version', 'fabric_artifact_kind',
    'fabric_java_major', 'fabric_runtime_mode', 'fabric_build_id',
    'fabric_codesource_sha256_observed', 'source_proxy', 'target_proxy',
    'federation_assertion_ttl_seconds', 'operator_visible_gui_attestation_count',
    'human_visible_federation_consent_count',
    'operator_visible_gui_attestation_schema', 'operator_visible_gui_attestation_source_mode',
    'operator_visible_gui_tool', 'operator_visible_gui_session_id',
    'operator_visible_gui_window_id','operator_visible_gui_client_process_id',
    'operator_visible_gui_client_process_started_at','operator_visible_gui_attempt_id',
    'operator_visible_gui_gui_attempt_id','operator_visible_gui_signing_request_schema',
    'operator_visible_gui_signing_request_domain','operator_visible_gui_signing_request_sha256',
    'operator_visible_gui_signing_request_size_bytes',
    'operator_visible_gui_signing_request_path_sha256',
    'operator_visible_gui_screenshot_path_sha256',
    'operator_visible_gui_attestation_output_path_sha256',
    'operator_visible_gui_captured_at','operator_visible_gui_signed_at',
    'operator_visible_gui_source_commit','operator_visible_gui_signer_key_id',
    'operator_visible_gui_trust_root_sha256','operator_visible_gui_signature_algorithm',
    'operator_visible_gui_attestation_json_sha256',
    'operator_visible_gui_attestation_json_size_bytes',
    'operator_visible_gui_screenshot_sha256', 'operator_visible_gui_screenshot_size_bytes',
    'operator_visible_gui_screenshot_width', 'operator_visible_gui_screenshot_height',
    'operator_visible_gui_screenshot_decoded_pixel_sha256',
    'release_bundle_manifest_sha256','release_bundle_fabric_jar_file',
    'release_bundle_fabric_jar_sha256','release_bundle_fabric_jar_size_bytes',
    'runtime_ledger_sha256','runtime_ledger_size_bytes','runtime_ledger_event_count',
    'runtime_ledger_head_sha256','runtime_ledger_supervisor_seal_sha256',
    'source_negative_attempt_id','source_negative_peer','source_negative_connection_id',
    'source_negative_session_id','source_negative_subject_commitment_sha256',
    'target_negative_attempt_id','target_negative_peer','target_negative_connection_id',
    'target_negative_session_id','target_negative_subject_commitment_sha256',
    'operator_attested_visible_computer_use_session',
    'operator_attested_no_headless_or_synthetic_input',
    'external_visible_gui_attestation_validated',
    'raw_peer_evidence_used', 'raw_content_retained', 'fabric_artifact_mode_verified',
    'source_local_auth_verified', 'source_paper_admission_verified',
    'enablement_consent_requested', 'enablement_consent_rendered',
    'enablement_consent_accepted', 'source_export_permit_reserved',
    'source_grant_stored_memory_only', 'source_grant_ready_observed',
    'source_disconnected_before_target_auth', 'target_local_auth_verified',
    'target_import_consent_inherited', 'presentation_sent',
    'target_authorization_promoted_after_presentation',
    'source_second_assertion_runtime_requested',
    'source_second_assertion_fabric_one_shot_rejection_observed',
    'source_second_assertion_fabric_rejection_count_delta',
    'source_second_assertion_grant_ready_delta',
    'target_inherited_export_runtime_requested',
    'target_inherited_export_fabric_rejection_observed',
    'target_inherited_export_fabric_rejection_count_delta',
    'target_inherited_export_grant_ready_delta',
    'target_observation_recorded', 'target_subject_bound',
    'target_observation_status_count_one', 'target_observation_status_one_before_expiry',
    'target_paper_admission_verified', 'local_trust_risk_admission_unchanged',
    'target_session_connected_through_expiry', 'observation_expired',
    'target_observation_status_zero_after_expiry', 'client_shutdown_completed',
    'cleanup_ports_free', 'remaining_owned_process_count', 'passed'
)

function Assert-PassingReportRaw(
        [string]$Raw,
        [System.Collections.IDictionary]$Current,
        [string]$ExpectedSource,
        [string]$ExpectedTarget) {
    try { $report = ConvertFrom-StrictJson $Raw }
    catch { throw 'FABRIC_FEDERATION_GUI_REPORT_JSON_INVALID' }
    if (-not (Test-ExactJsonProperties $report $reportPropertyNames)) {
        throw 'FABRIC_FEDERATION_GUI_REPORT_SCHEMA_INVALID'
    }
    foreach ($name in @(
            'schema', 'generated_at', 'source_mode', 'status', 'artifact_class',
            'source_commit','run_attempt_id','gui_attempt_id','gui_challenge_nonce','gui_challenge_issued_at',
            'gui_signing_request_created_at','gui_signing_request_expires_at',
            'fabric_client_started_at','gui_prompt_rendered_at','enablement_consent_accepted_at',
            'fabric_target', 'minecraft_version', 'fabric_api_version', 'fabric_artifact_kind',
            'fabric_runtime_mode', 'fabric_build_id', 'fabric_codesource_sha256_observed',
            'source_proxy', 'target_proxy', 'operator_visible_gui_attestation_schema',
            'operator_visible_gui_attestation_source_mode', 'operator_visible_gui_tool',
            'operator_visible_gui_session_id','operator_visible_gui_window_id',
            'operator_visible_gui_client_process_started_at','operator_visible_gui_attempt_id',
            'operator_visible_gui_gui_attempt_id','operator_visible_gui_signing_request_schema',
            'operator_visible_gui_signing_request_domain','operator_visible_gui_signing_request_sha256',
            'operator_visible_gui_signing_request_path_sha256',
            'operator_visible_gui_screenshot_path_sha256',
            'operator_visible_gui_attestation_output_path_sha256',
            'operator_visible_gui_captured_at','operator_visible_gui_signed_at',
            'operator_visible_gui_source_commit','operator_visible_gui_signer_key_id',
            'operator_visible_gui_trust_root_sha256','operator_visible_gui_signature_algorithm',
            'operator_visible_gui_attestation_json_sha256','operator_visible_gui_screenshot_sha256',
            'operator_visible_gui_screenshot_decoded_pixel_sha256','release_bundle_manifest_sha256',
            'release_bundle_fabric_jar_file','release_bundle_fabric_jar_sha256',
            'runtime_ledger_sha256','runtime_ledger_head_sha256','runtime_ledger_supervisor_seal_sha256',
            'source_negative_attempt_id','source_negative_peer','source_negative_connection_id',
            'source_negative_session_id','source_negative_subject_commitment_sha256',
            'target_negative_attempt_id','target_negative_peer','target_negative_connection_id',
            'target_negative_session_id','target_negative_subject_commitment_sha256')) {
        if (-not (Test-JsonString $report.$name)) {
            throw "FABRIC_FEDERATION_GUI_REPORT_TYPE_INVALID: $name"
        }
    }
    foreach ($name in @(
            'operator_attested_visible_computer_use_session',
            'operator_attested_no_headless_or_synthetic_input',
            'external_visible_gui_attestation_validated',
            'raw_peer_evidence_used', 'raw_content_retained',
            'fabric_artifact_mode_verified', 'source_local_auth_verified',
            'source_paper_admission_verified', 'enablement_consent_requested',
            'enablement_consent_rendered', 'enablement_consent_accepted',
            'source_export_permit_reserved', 'source_grant_stored_memory_only',
            'source_grant_ready_observed', 'source_disconnected_before_target_auth',
            'target_local_auth_verified', 'target_import_consent_inherited',
            'presentation_sent', 'target_authorization_promoted_after_presentation',
            'source_second_assertion_runtime_requested',
            'source_second_assertion_fabric_one_shot_rejection_observed',
            'target_inherited_export_runtime_requested',
            'target_inherited_export_fabric_rejection_observed',
            'target_observation_recorded', 'target_subject_bound',
            'target_observation_status_count_one', 'target_observation_status_one_before_expiry',
            'target_paper_admission_verified', 'local_trust_risk_admission_unchanged',
            'target_session_connected_through_expiry', 'observation_expired',
            'target_observation_status_zero_after_expiry',
            'client_shutdown_completed', 'cleanup_ports_free', 'passed')) {
        if (-not (Test-JsonBoolean $report.$name)) {
            throw "FABRIC_FEDERATION_GUI_REPORT_TYPE_INVALID: $name"
        }
    }
    foreach ($name in @(
            'fabric_java_major', 'federation_assertion_ttl_seconds',
            'operator_visible_gui_attestation_count', 'human_visible_federation_consent_count',
            'operator_visible_gui_attestation_json_size_bytes',
            'operator_visible_gui_signing_request_size_bytes',
            'operator_visible_gui_screenshot_size_bytes',
            'operator_visible_gui_screenshot_width', 'operator_visible_gui_screenshot_height',
            'operator_visible_gui_client_process_id','release_bundle_fabric_jar_size_bytes',
            'runtime_ledger_size_bytes','runtime_ledger_event_count',
            'source_second_assertion_grant_ready_delta',
            'source_second_assertion_fabric_rejection_count_delta',
            'target_inherited_export_fabric_rejection_count_delta',
            'target_inherited_export_grant_ready_delta',
            'remaining_owned_process_count')) {
        if (-not (Test-JsonInteger $report.$name)) {
            throw "FABRIC_FEDERATION_GUI_REPORT_INTEGER_TYPE_INVALID: $name"
        }
    }
    $timestamp = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            [string]$report.generated_at, 'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None, [ref]$timestamp)) {
        throw 'FABRIC_FEDERATION_GUI_REPORT_TIMESTAMP_INVALID'
    }
    $age = [DateTimeOffset]::UtcNow - $timestamp
    if ($age.TotalMinutes -lt 0 -or $age.TotalMinutes -gt $MaximumReportAgeMinutes) {
        throw 'FABRIC_FEDERATION_GUI_REPORT_STALE'
    }
    $requiredTrue = @(
        'operator_attested_visible_computer_use_session',
        'operator_attested_no_headless_or_synthetic_input',
        'external_visible_gui_attestation_validated',
        'fabric_artifact_mode_verified', 'source_local_auth_verified',
        'source_paper_admission_verified', 'enablement_consent_requested',
        'enablement_consent_rendered', 'enablement_consent_accepted',
        'source_export_permit_reserved', 'source_grant_stored_memory_only',
        'source_grant_ready_observed', 'source_disconnected_before_target_auth',
        'target_local_auth_verified', 'target_import_consent_inherited',
        'presentation_sent', 'target_authorization_promoted_after_presentation',
        'source_second_assertion_runtime_requested',
        'source_second_assertion_fabric_one_shot_rejection_observed',
        'target_inherited_export_runtime_requested',
        'target_inherited_export_fabric_rejection_observed',
        'target_observation_recorded', 'target_subject_bound',
        'target_observation_status_count_one', 'target_observation_status_one_before_expiry',
        'target_paper_admission_verified', 'local_trust_risk_admission_unchanged',
        'target_session_connected_through_expiry', 'observation_expired',
        'target_observation_status_zero_after_expiry',
        'client_shutdown_completed', 'cleanup_ports_free', 'passed'
    )
    foreach ($name in $requiredTrue) {
        if (-not [bool]$report.$name) {
            throw "FABRIC_FEDERATION_GUI_REQUIRED_ASSERTION_FALSE: $name"
        }
    }
    if ($report.schema -cne $reportSchema -or
            $report.source_mode -cne 'EXECUTED_REAL_FABRIC_GUI' -or
            $report.status -cne 'passed' -or $report.artifact_class -cne $artifactClass -or
            $report.source_commit -cne [string]$Current.source_commit -or
            $report.fabric_target -cne $FabricTarget -or
            $report.minecraft_version -cne [string]$fabricDescriptor.minecraft_version -or
            $report.fabric_api_version -cne [string]$fabricDescriptor.fabric_api_version -or
            $report.fabric_artifact_kind -cne [string]$fabricDescriptor.artifact_kind -or
            [int]$report.fabric_java_major -ne [int]$fabricDescriptor.java_major -or
            $report.fabric_runtime_mode -cne $fabricRuntimeMode -or
            $report.fabric_build_id -cne [string]$Current.fabric_build_id -or
            $report.fabric_codesource_sha256_observed -cne [string]$Current.fabric_artifact_sha256 -or
            $report.source_proxy -cne $ExpectedSource -or $report.target_proxy -cne $ExpectedTarget -or
            [int]$report.federation_assertion_ttl_seconds -lt 60 -or
            [int]$report.federation_assertion_ttl_seconds -gt 300 -or
            [int]$report.operator_visible_gui_attestation_count -ne 1 -or
            [int]$report.human_visible_federation_consent_count -ne 1 -or
            $report.operator_visible_gui_attestation_schema -cne $visibleGuiAttestationSchema -or
            $report.operator_visible_gui_signing_request_schema -cne $visibleGuiSigningRequestSchema -or
            $report.operator_visible_gui_signing_request_domain -cne $visibleGuiSigningRequestDomain -or
            $report.operator_visible_gui_attestation_source_mode -cne $visibleGuiAttestationSourceMode -or
            $report.operator_visible_gui_tool -cne 'computer-use' -or
            $report.operator_visible_gui_source_commit -cne [string]$Current.source_commit -or
            $report.run_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            $report.gui_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            $report.gui_challenge_nonce -cnotmatch '^[0-9a-f]{64}$' -or
            $report.operator_visible_gui_window_id -cnotmatch '^(?:0x)?[0-9a-fA-F]{1,16}$' -or
            [int]$report.operator_visible_gui_client_process_id -le 0 -or
            $report.operator_visible_gui_signer_key_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$' -or
            -not (Test-Sha256 $report.operator_visible_gui_attestation_json_sha256) -or
            -not (Test-Sha256 $report.operator_visible_gui_signing_request_sha256) -or
            -not (Test-Sha256 $report.operator_visible_gui_signing_request_path_sha256) -or
            -not (Test-Sha256 $report.operator_visible_gui_screenshot_path_sha256) -or
            -not (Test-Sha256 $report.operator_visible_gui_attestation_output_path_sha256) -or
            -not (Test-Sha256 $report.operator_visible_gui_screenshot_sha256) -or
            -not (Test-Sha256 $report.operator_visible_gui_screenshot_decoded_pixel_sha256) -or
            $report.operator_visible_gui_attempt_id -cne $report.run_attempt_id -or
            $report.operator_visible_gui_gui_attempt_id -cne $report.gui_attempt_id -or
            $report.operator_visible_gui_trust_root_sha256 -cne $ExpectedVisibleGuiTrustRootSha256.ToLowerInvariant() -or
            $report.operator_visible_gui_signature_algorithm -cne 'RSA_PKCS1_SHA256' -or
            -not (Test-Sha256 $report.release_bundle_manifest_sha256) -or
            $report.release_bundle_fabric_jar_sha256 -cne [string]$Current.fabric_artifact_sha256 -or
            -not (Test-Sha256 $report.runtime_ledger_sha256) -or
            -not (Test-Sha256 $report.runtime_ledger_head_sha256) -or
            -not (Test-Sha256 $report.runtime_ledger_supervisor_seal_sha256) -or
            [int]$report.runtime_ledger_event_count -ne 18 -or
            $report.source_negative_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            $report.target_negative_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            $report.source_negative_connection_id -cnotmatch '^[0-9a-f]{32}$' -or
            $report.target_negative_connection_id -cnotmatch '^[0-9a-f]{32}$' -or
            $report.source_negative_session_id -cnotmatch '^[0-9a-f]{32}$' -or
            $report.target_negative_session_id -cnotmatch '^[0-9a-f]{32}$' -or
            -not (Test-Sha256 $report.source_negative_subject_commitment_sha256) -or
            -not (Test-Sha256 $report.target_negative_subject_commitment_sha256) -or
            $report.release_bundle_fabric_jar_file -cne "mcace-client-fabric-$FabricTarget.jar" -or
            [long]$report.operator_visible_gui_attestation_json_size_bytes -le 0 -or
            [long]$report.operator_visible_gui_screenshot_size_bytes -lt 128 -or
            [int]$report.operator_visible_gui_screenshot_width -lt 320 -or
            [int]$report.operator_visible_gui_screenshot_height -lt 200 -or
            [int]$report.source_second_assertion_grant_ready_delta -ne 0 -or
            [int]$report.source_second_assertion_fabric_rejection_count_delta -ne 1 -or
            [int]$report.target_inherited_export_fabric_rejection_count_delta -ne 1 -or
            [int]$report.target_inherited_export_grant_ready_delta -ne 0 -or
            [bool]$report.raw_peer_evidence_used -or [bool]$report.raw_content_retained -or
            [int]$report.remaining_owned_process_count -ne 0) {
        throw 'FABRIC_FEDERATION_GUI_REPORT_INVALID'
    }
    $startedAt = [DateTimeOffset]::MinValue
    $promptRenderedAt = [DateTimeOffset]::MinValue
    $acceptedAt = [DateTimeOffset]::MinValue
    $capturedAt = [DateTimeOffset]::MinValue
    $signedAt = [DateTimeOffset]::MinValue
    $challengeIssuedAt = [DateTimeOffset]::MinValue
    $clientProcessStartedAt = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact([string]$report.fabric_client_started_at, 'o',
            [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None,
            [ref]$startedAt) -or
            -not [DateTimeOffset]::TryParseExact([string]$report.gui_prompt_rendered_at, 'o',
            [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None,
            [ref]$promptRenderedAt) -or
            -not [DateTimeOffset]::TryParseExact([string]$report.enablement_consent_accepted_at, 'o',
            [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None,
            [ref]$acceptedAt) -or
            -not [DateTimeOffset]::TryParseExact([string]$report.operator_visible_gui_captured_at, 'o',
            [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None,
            [ref]$capturedAt) -or
            -not [DateTimeOffset]::TryParseExact([string]$report.operator_visible_gui_signed_at, 'o',
            [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None,
            [ref]$signedAt) -or
            -not [DateTimeOffset]::TryParseExact([string]$report.gui_challenge_issued_at, 'o',
            [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None,
            [ref]$challengeIssuedAt) -or
            -not [DateTimeOffset]::TryParseExact(
            [string]$report.operator_visible_gui_client_process_started_at, 'o',
            [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None,
            [ref]$clientProcessStartedAt) -or
            $clientProcessStartedAt.ToUniversalTime().Ticks -gt $promptRenderedAt.ToUniversalTime().Ticks -or
            $challengeIssuedAt.ToUniversalTime().Ticks -gt $promptRenderedAt.ToUniversalTime().Ticks -or
            $promptRenderedAt.ToUniversalTime().Ticks -lt $startedAt.ToUniversalTime().Ticks -or
            $capturedAt.ToUniversalTime().Ticks -lt $promptRenderedAt.ToUniversalTime().Ticks -or
            $capturedAt.ToUniversalTime().Ticks -gt $acceptedAt.ToUniversalTime().Ticks -or
            $signedAt.ToUniversalTime().Ticks -lt $capturedAt.ToUniversalTime().Ticks -or
            $signedAt.ToUniversalTime().Ticks -gt $acceptedAt.ToUniversalTime().Ticks) {
        throw 'FABRIC_FEDERATION_GUI_REPORT_VISIBLE_CAPTURE_WINDOW_INVALID'
    }
    return $report
}

function Assert-BindingRaw(
        [string]$Raw,
        [string]$ReportSha256,
        [object]$Report,
        [System.Collections.IDictionary]$Current) {
    try { $binding = ConvertFrom-StrictJson $Raw }
    catch { throw 'FABRIC_FEDERATION_GUI_BINDING_JSON_INVALID' }
    $names = @(
        'schema', 'report_schema', 'report_generated_at', 'report_sha256',
        'source_mode', 'source_proxy', 'target_proxy',
        'visible_gui_trust_root_sha256',
        'visible_gui_attestation_sha256', 'visible_gui_attestation_size_bytes',
        'visible_gui_screenshot_sha256', 'visible_gui_screenshot_size_bytes',
        'visible_gui_screenshot_width','visible_gui_screenshot_height',
        'visible_gui_screenshot_decoded_pixel_sha256',
        'runtime_ledger_sha256','runtime_ledger_size_bytes','runtime_ledger_event_count',
        'runtime_ledger_head_sha256','runtime_ledger_supervisor_seal_sha256',
        'release_bundle_manifest_sha256','release_bundle_fabric_jar_sha256','passed'
    ) + @($Current.Keys)
    if (-not (Test-ExactJsonProperties $binding $names)) {
        throw 'FABRIC_FEDERATION_GUI_BINDING_SCHEMA_INVALID'
    }
    foreach ($name in @('schema', 'report_schema', 'report_generated_at', 'report_sha256',
            'source_mode','source_proxy','target_proxy','visible_gui_trust_root_sha256',
            'visible_gui_attestation_sha256','visible_gui_screenshot_sha256',
            'visible_gui_screenshot_decoded_pixel_sha256','runtime_ledger_sha256',
            'runtime_ledger_head_sha256','runtime_ledger_supervisor_seal_sha256',
            'release_bundle_manifest_sha256','release_bundle_fabric_jar_sha256')) {
        if (-not (Test-JsonString $binding.$name)) {
            throw "FABRIC_FEDERATION_GUI_BINDING_TYPE_INVALID: $name"
        }
    }
    foreach ($name in @('visible_gui_attestation_size_bytes','visible_gui_screenshot_size_bytes',
            'visible_gui_screenshot_width','visible_gui_screenshot_height',
            'runtime_ledger_size_bytes','runtime_ledger_event_count')) {
        if (-not (Test-JsonInteger $binding.$name)) {
            throw "FABRIC_FEDERATION_GUI_BINDING_INTEGER_TYPE_INVALID: $name"
        }
    }
    if ($binding.schema -cne $bindingSchema -or $binding.report_schema -cne $reportSchema -or
            $binding.report_generated_at -cne $Report.generated_at -or
            $binding.report_sha256 -cne $ReportSha256 -or
            $binding.source_mode -cne 'EXECUTED_REAL_FABRIC_GUI' -or
            $binding.source_proxy -cne $Report.source_proxy -or
            $binding.target_proxy -cne $Report.target_proxy -or
            $binding.visible_gui_trust_root_sha256 -cne $Report.operator_visible_gui_trust_root_sha256 -or
            $binding.visible_gui_attestation_sha256 -cne $Report.operator_visible_gui_attestation_json_sha256 -or
            [long]$binding.visible_gui_attestation_size_bytes -ne [long]$Report.operator_visible_gui_attestation_json_size_bytes -or
            $binding.visible_gui_screenshot_sha256 -cne $Report.operator_visible_gui_screenshot_sha256 -or
            [long]$binding.visible_gui_screenshot_size_bytes -ne [long]$Report.operator_visible_gui_screenshot_size_bytes -or
            [int]$binding.visible_gui_screenshot_width -ne [int]$Report.operator_visible_gui_screenshot_width -or
            [int]$binding.visible_gui_screenshot_height -ne [int]$Report.operator_visible_gui_screenshot_height -or
            $binding.visible_gui_screenshot_decoded_pixel_sha256 -cne $Report.operator_visible_gui_screenshot_decoded_pixel_sha256 -or
            $binding.runtime_ledger_sha256 -cne $Report.runtime_ledger_sha256 -or
            [long]$binding.runtime_ledger_size_bytes -ne [long]$Report.runtime_ledger_size_bytes -or
            [int]$binding.runtime_ledger_event_count -ne [int]$Report.runtime_ledger_event_count -or
            $binding.runtime_ledger_head_sha256 -cne $Report.runtime_ledger_head_sha256 -or
            $binding.runtime_ledger_supervisor_seal_sha256 -cne $Report.runtime_ledger_supervisor_seal_sha256 -or
            $binding.release_bundle_manifest_sha256 -cne $Report.release_bundle_manifest_sha256 -or
            $binding.release_bundle_fabric_jar_sha256 -cne $Report.release_bundle_fabric_jar_sha256 -or
            -not (Test-JsonBoolean $binding.passed) -or -not [bool]$binding.passed) {
        throw 'FABRIC_FEDERATION_GUI_BINDING_INVALID'
    }
    foreach ($name in @($Current.Keys)) {
        $expected = $Current[$name]
        $actual = $binding.$name
        if ($expected -is [bool]) {
            if (-not (Test-JsonBoolean $actual) -or [bool]$actual -ne [bool]$expected) {
                throw "FABRIC_FEDERATION_GUI_BINDING_CURRENT_MISMATCH: $name"
            }
        } elseif ($expected -is [byte] -or $expected -is [int16] -or
                $expected -is [int32] -or $expected -is [int64]) {
            if (-not (Test-JsonInteger $actual) -or [long]$actual -ne [long]$expected) {
                throw "FABRIC_FEDERATION_GUI_BINDING_CURRENT_MISMATCH: $name"
            }
        } elseif (-not (Test-JsonString $actual) -or [string]$actual -cne [string]$expected) {
            throw "FABRIC_FEDERATION_GUI_BINDING_CURRENT_MISMATCH: $name"
        }
    }
    return $binding
}

function Assert-CommitRaw(
        [string]$Raw,
        [string]$ReportSha256,
        [string]$BindingSha256,
        [object]$Report,
        [object]$PostRunReceiptEvidence,
        [object]$PostRunReceipt) {
    try { $commit = ConvertFrom-StrictJson $Raw }
    catch { throw 'FABRIC_FEDERATION_GUI_COMMIT_JSON_INVALID' }
    $names = @(
        'schema', 'report_schema', 'binding_schema', 'generated_at', 'report_sha256',
        'binding_sha256', 'visible_gui_attestation_sha256', 'visible_gui_screenshot_sha256',
        'runtime_ledger_sha256','runtime_ledger_head_sha256','runtime_ledger_supervisor_seal_sha256',
        'release_bundle_manifest_sha256','release_bundle_fabric_jar_sha256',
        'postrun_receipt_schema','postrun_receipt_sha256','postrun_receipt_size_bytes',
        'postrun_trust_root_sha256','postrun_signer_key_id','postrun_operation_attempt_id',
        'postrun_challenge_nonce',
        'fabric_target', 'source_proxy', 'target_proxy', 'passed'
    )
    if (-not (Test-ExactJsonProperties $commit $names)) {
        throw 'FABRIC_FEDERATION_GUI_COMMIT_SCHEMA_INVALID'
    }
    foreach ($name in @('schema', 'report_schema', 'binding_schema', 'generated_at',
            'report_sha256', 'binding_sha256', 'visible_gui_attestation_sha256',
            'visible_gui_screenshot_sha256','runtime_ledger_sha256','runtime_ledger_head_sha256',
            'runtime_ledger_supervisor_seal_sha256','release_bundle_manifest_sha256',
            'release_bundle_fabric_jar_sha256','postrun_receipt_schema','postrun_receipt_sha256',
            'postrun_trust_root_sha256','postrun_signer_key_id','postrun_operation_attempt_id',
            'postrun_challenge_nonce','fabric_target','source_proxy','target_proxy')) {
        if (-not (Test-JsonString $commit.$name)) {
            throw "FABRIC_FEDERATION_GUI_COMMIT_TYPE_INVALID: $name"
        }
    }
    if (-not (Test-JsonInteger $commit.postrun_receipt_size_bytes)) {
        throw 'FABRIC_FEDERATION_GUI_COMMIT_POSTRUN_SIZE_TYPE_INVALID'
    }
    if (
            $commit.schema -cne $commitSchema -or $commit.report_schema -cne $reportSchema -or
            $commit.binding_schema -cne $bindingSchema -or
            $commit.generated_at -cne $Report.generated_at -or
            $commit.report_sha256 -cne $ReportSha256 -or
            $commit.binding_sha256 -cne $BindingSha256 -or
            $commit.visible_gui_attestation_sha256 -cne $Report.operator_visible_gui_attestation_json_sha256 -or
            $commit.visible_gui_screenshot_sha256 -cne $Report.operator_visible_gui_screenshot_sha256 -or
            $commit.runtime_ledger_sha256 -cne $Report.runtime_ledger_sha256 -or
            $commit.runtime_ledger_head_sha256 -cne $Report.runtime_ledger_head_sha256 -or
            $commit.runtime_ledger_supervisor_seal_sha256 -cne $Report.runtime_ledger_supervisor_seal_sha256 -or
            $commit.release_bundle_manifest_sha256 -cne $Report.release_bundle_manifest_sha256 -or
            $commit.release_bundle_fabric_jar_sha256 -cne $Report.release_bundle_fabric_jar_sha256 -or
            $commit.postrun_receipt_schema -cne $postRunReceiptSchema -or
            $commit.postrun_receipt_sha256 -cne [string]$PostRunReceiptEvidence.sha256 -or
            [long]$commit.postrun_receipt_size_bytes -ne [long]$PostRunReceiptEvidence.size_bytes -or
            $commit.postrun_trust_root_sha256 -cne [string]$PostRunReceipt.signer_trust_root_sha256 -or
            $commit.postrun_signer_key_id -cne [string]$PostRunReceipt.signer_key_id -or
            $commit.postrun_operation_attempt_id -cne [string]$PostRunReceipt.postrun_operation_attempt_id -or
            $commit.postrun_challenge_nonce -cne [string]$PostRunReceipt.postrun_challenge_nonce -or
            $commit.fabric_target -cne $Report.fabric_target -or
            $commit.source_proxy -cne $Report.source_proxy -or
            $commit.target_proxy -cne $Report.target_proxy -or
            -not (Test-JsonBoolean $commit.passed) -or -not [bool]$commit.passed) {
        throw 'FABRIC_FEDERATION_GUI_COMMIT_INVALID'
    }
    return $commit
}

function Assert-ExactFederationEvidenceDirectory([string]$Directory) {
    $resolved = Assert-DirectLocalPath $Directory -Directory
    $entries = @(Get-ChildItem -LiteralPath $resolved -Force -ErrorAction Stop)
    $expected = @('binding.json','commit.json','report.json','runtime-events.jsonl',
        'visible-gui-attestation.json','visible-gui-signing-request.json','visible-gui.png',
        'post-run-receipt.json')
    if ($entries.Count -ne $expected.Count -or
            ((@($entries.Name | Sort-Object) -join '|') -cne (($expected | Sort-Object) -join '|'))) {
        throw 'FABRIC_FEDERATION_GUI_EVIDENCE_FILE_SET_INVALID'
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or
                ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($entry.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0) {
            throw 'FABRIC_FEDERATION_GUI_EVIDENCE_FILE_TYPE_INVALID'
        }
    }
}

function Assert-EvidenceSet(
        [string]$ReportPath,
        [System.Collections.IDictionary]$Current,
        [string]$ExpectedSource,
        [string]$ExpectedTarget,
        [object]$VisibleGuiTrustRootEvidence,
        [object]$PostRunSupervisorTrustRootEvidence,
        [object]$ReleaseBinding,
        [string]$ApprovedVisibleGuiPin,
        [string]$ApprovedPostRunPin) {
    $reportEvidence = $null
    $bindingEvidence = $null
    $commitEvidence = $null
    $attestationEvidence = $null
    $signingRequestEvidence = $null
    $screenshotEvidence = $null
    $ledgerEvidence = $null
    $postRunReceiptEvidence = $null
    try {
        $directory = Split-Path -Parent $ReportPath
        Assert-ExactFederationEvidenceDirectory $directory
        $reportEvidence = Open-LockedEvidence $ReportPath
        $bindingEvidence = Open-LockedEvidence (Join-Path $directory 'binding.json')
        $commitEvidence = Open-LockedEvidence (Join-Path $directory 'commit.json')
        $attestationEvidence = Open-LockedEvidence (Join-Path $directory 'visible-gui-attestation.json')
        $signingRequestEvidence = Open-LockedEvidence `
            (Join-Path $directory 'visible-gui-signing-request.json')
        $screenshotEvidence = Open-LockedBinaryEvidence (Join-Path $directory 'visible-gui.png')
        $ledgerEvidence = Open-LockedFileBytes (Join-Path $directory 'runtime-events.jsonl') 256 1048576 'RUNTIME_LEDGER'
        $postRunReceiptEvidence = Open-LockedEvidence (Join-Path $directory 'post-run-receipt.json')
        $report = Assert-PassingReportRaw $reportEvidence.raw $Current $ExpectedSource $ExpectedTarget
        $promptAt = [DateTimeOffset]::ParseExact(
            [string]$report.gui_prompt_rendered_at, 'o', [Globalization.CultureInfo]::InvariantCulture)
        $acceptedAt = [DateTimeOffset]::ParseExact(
            [string]$report.enablement_consent_accepted_at, 'o', [Globalization.CultureInfo]::InvariantCulture)
        $requestPreview = ConvertFrom-StrictJson $signingRequestEvidence.raw
        $requestExpected = [ordered]@{}
        foreach ($name in $visibleGuiSigningRequestPropertyNames) {
            $requestExpected[$name] = $requestPreview.$name
        }
        $validatedSigningRequest = Assert-VisibleGuiSigningRequest `
            $signingRequestEvidence $screenshotEvidence $requestExpected $acceptedAt
        $validatedAttestation = Assert-VisibleGuiAttestation `
            $attestationEvidence $screenshotEvidence $signingRequestEvidence `
            $validatedSigningRequest $VisibleGuiTrustRootEvidence `
            $ExpectedVisibleGuiTrustRootSha256 $promptAt $acceptedAt `
            ([string]$Current.source_commit) $FabricTarget ([string]$Current.fabric_artifact_sha256) `
            ([string]$report.run_attempt_id) ([string]$report.gui_attempt_id) `
            ([string]$report.gui_challenge_nonce) `
            ([DateTimeOffset]::ParseExact([string]$report.gui_challenge_issued_at, 'o', `
                [Globalization.CultureInfo]::InvariantCulture)) `
            ([int]$report.operator_visible_gui_client_process_id) `
            ([string]$report.operator_visible_gui_client_process_started_at) `
            $ApprovedVisibleGuiPin
        $ledger = Assert-RuntimeLedgerBytes $ledgerEvidence.bytes ([string]$Current.source_commit) `
            $FabricTarget ([string]$report.run_attempt_id) ([string]$report.gui_challenge_nonce)
        if ($signingRequestEvidence.sha256 -cne
                    $report.operator_visible_gui_signing_request_sha256 -or
                [long]$signingRequestEvidence.size_bytes -ne
                    [long]$report.operator_visible_gui_signing_request_size_bytes -or
                [string]$requestPreview.schema -cne
                    [string]$report.operator_visible_gui_signing_request_schema -or
                [string]$requestPreview.domain -cne
                    [string]$report.operator_visible_gui_signing_request_domain -or
                [string]$requestPreview.source_commit -cne [string]$Current.source_commit -or
                [string]$requestPreview.artifact_source_commit -cne
                    [string]$ReleaseBinding.artifact_source_commit -or
                [string]$requestPreview.product_version -cne [string]$ReleaseBinding.product_version -or
                [string]$requestPreview.fabric_target -cne $FabricTarget -or
                [string]$requestPreview.source_proxy -cne $ExpectedSource -or
                [string]$requestPreview.target_proxy -cne $ExpectedTarget -or
                [string]$requestPreview.release_bundle_manifest_sha256 -cne
                    [string]$ReleaseBinding.manifest_sha256 -or
                [string]$requestPreview.final_fabric_jar_sha256 -cne
                    [string]$ReleaseBinding.fabric_jar_sha256 -or
                [string]$requestPreview.run_attempt_id -cne [string]$report.run_attempt_id -or
                [string]$requestPreview.gui_attempt_id -cne [string]$report.gui_attempt_id -or
                [string]$requestPreview.challenge_nonce -cne [string]$report.gui_challenge_nonce -or
                [string]$requestPreview.request_created_at -cne
                    [string]$report.gui_signing_request_created_at -or
                [string]$requestPreview.expires_at -cne
                    [string]$report.gui_signing_request_expires_at -or
                [string]$requestPreview.signing_request_path_sha256 -cne
                    [string]$report.operator_visible_gui_signing_request_path_sha256 -or
                [string]$requestPreview.screenshot_path_sha256 -cne
                    [string]$report.operator_visible_gui_screenshot_path_sha256 -or
                [string]$requestPreview.attestation_output_path_sha256 -cne
                    [string]$report.operator_visible_gui_attestation_output_path_sha256 -or
                $attestationEvidence.sha256 -cne $report.operator_visible_gui_attestation_json_sha256 -or
                [long]$attestationEvidence.size_bytes -ne [long]$report.operator_visible_gui_attestation_json_size_bytes -or
                $screenshotEvidence.sha256 -cne $report.operator_visible_gui_screenshot_sha256 -or
                [long]$screenshotEvidence.size_bytes -ne [long]$report.operator_visible_gui_screenshot_size_bytes -or
                [string]$validatedAttestation.captured_at -cne [string]$report.operator_visible_gui_captured_at -or
                [string]$validatedAttestation.signed_at -cne [string]$report.operator_visible_gui_signed_at -or
                [string]$validatedAttestation.value.session_id -cne [string]$report.operator_visible_gui_session_id -or
                [string]$validatedAttestation.screenshot_decoded_pixel_sha256 -cne [string]$report.operator_visible_gui_screenshot_decoded_pixel_sha256 -or
                $ledgerEvidence.sha256 -cne [string]$report.runtime_ledger_sha256 -or
                [long]$ledgerEvidence.size_bytes -ne [long]$report.runtime_ledger_size_bytes -or
                [int]$ledger.event_count -ne [int]$report.runtime_ledger_event_count -or
                [string]$ledger.head_sha256 -cne [string]$report.runtime_ledger_head_sha256 -or
                [string]$ledger.supervisor_seal_sha256 -cne [string]$report.runtime_ledger_supervisor_seal_sha256 -or
                [string]$ledger.gui_receipt_attestation_sha256 -cne [string]$attestationEvidence.sha256 -or
                [string]$ledger.source_negative_attempt_id -cne [string]$report.source_negative_attempt_id -or
                [string]$ledger.source_negative_peer -cne [string]$report.source_negative_peer -or
                [string]$ledger.source_negative_connection_id -cne [string]$report.source_negative_connection_id -or
                [string]$ledger.source_negative_session_id -cne [string]$report.source_negative_session_id -or
                [string]$ledger.source_negative_subject_commitment_sha256 -cne [string]$report.source_negative_subject_commitment_sha256 -or
                [string]$ledger.target_negative_attempt_id -cne [string]$report.target_negative_attempt_id -or
                [string]$ledger.target_negative_peer -cne [string]$report.target_negative_peer -or
                [string]$ledger.target_negative_connection_id -cne [string]$report.target_negative_connection_id -or
                [string]$ledger.target_negative_session_id -cne [string]$report.target_negative_session_id -or
                [string]$ledger.target_negative_subject_commitment_sha256 -cne [string]$report.target_negative_subject_commitment_sha256 -or
                [string]$ReleaseBinding.manifest_sha256 -cne [string]$report.release_bundle_manifest_sha256 -or
                [string]$ReleaseBinding.fabric_jar_sha256 -cne [string]$report.release_bundle_fabric_jar_sha256 -or
                [string]$ReleaseBinding.fabric_jar_file -cne [string]$report.release_bundle_fabric_jar_file -or
                [string]$ReleaseBinding.artifact_source_commit -cne [string]$report.source_commit -or
                [long]$ReleaseBinding.fabric_jar_size_bytes -ne [long]$report.release_bundle_fabric_jar_size_bytes) {
            throw 'FABRIC_FEDERATION_GUI_EXTERNAL_ATTESTATION_REPORT_BINDING_INVALID'
        }
        $binding = Assert-BindingRaw $bindingEvidence.raw $reportEvidence.sha256 $report $Current
        $receiptPreview = ConvertFrom-StrictJson $postRunReceiptEvidence.raw
        if (-not (Test-ExactJsonProperties $receiptPreview $postRunReceiptPropertyNames)) {
            throw 'FABRIC_FEDERATION_GUI_POSTRUN_RECEIPT_SCHEMA_INVALID'
        }
        $postRunChallengeIssuedAt = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParseExact(
                [string]$receiptPreview.postrun_challenge_issued_at, 'o',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::None, [ref]$postRunChallengeIssuedAt)) {
            throw 'FABRIC_FEDERATION_GUI_POSTRUN_CHALLENGE_TIME_INVALID'
        }
        $validatedGuiRoot = Assert-VisibleGuiTrustRoot $VisibleGuiTrustRootEvidence `
            $ExpectedVisibleGuiTrustRootSha256 $ApprovedVisibleGuiPin
        $validatedPostRunRoot = Assert-PostRunSupervisorTrustRoot `
            $PostRunSupervisorTrustRootEvidence $ExpectedPostRunSupervisorTrustRootSha256 `
            $ApprovedPostRunPin
        Assert-DistinctFederationSignerRoots $validatedGuiRoot $validatedPostRunRoot
        $postRunExpected = Get-PostRunReceiptExpectedBinding `
            $ReleaseBinding $report $reportEvidence $bindingEvidence $attestationEvidence `
            $screenshotEvidence $validatedAttestation $ledgerEvidence $ledger `
            ([string]$receiptPreview.postrun_operation_attempt_id) `
            ([string]$receiptPreview.postrun_challenge_nonce) `
            ([string]$receiptPreview.postrun_challenge_issued_at)
        $validatedPostRunReceipt = Assert-PostRunReceipt $postRunReceiptEvidence `
            $PostRunSupervisorTrustRootEvidence $ExpectedPostRunSupervisorTrustRootSha256 `
            $ApprovedPostRunPin $postRunExpected $postRunChallengeIssuedAt
        $null = Assert-CommitRaw $commitEvidence.raw $reportEvidence.sha256 `
            $bindingEvidence.sha256 $report $postRunReceiptEvidence $validatedPostRunReceipt.value
        return $report
    } finally {
        if ($null -ne $postRunReceiptEvidence) { $postRunReceiptEvidence.stream.Dispose() }
        if ($null -ne $ledgerEvidence) { $ledgerEvidence.stream.Dispose() }
        if ($null -ne $screenshotEvidence) { $screenshotEvidence.stream.Dispose() }
        if ($null -ne $signingRequestEvidence) { $signingRequestEvidence.stream.Dispose() }
        if ($null -ne $attestationEvidence) { $attestationEvidence.stream.Dispose() }
        if ($null -ne $commitEvidence) { $commitEvidence.stream.Dispose() }
        if ($null -ne $bindingEvidence) { $bindingEvidence.stream.Dispose() }
        if ($null -ne $reportEvidence) { $reportEvidence.stream.Dispose() }
    }
}

function Get-LatestCompleteEvidenceReport {
    if (-not (Test-Path -LiteralPath $evidenceRunsRoot -PathType Container)) { return $null }
    $root = Assert-DirectLocalPath $evidenceRunsRoot -Directory
    $targetLeaf = $FabricTarget.Replace('.', '_')
    $leafPattern = '^[0-9]{8}T[0-9]{9}Z-{0}-{1}-to-{2}-[0-9a-f]{{32}}$' -f
        [regex]::Escape($targetLeaf), [regex]::Escape($SourceProxy), [regex]::Escape($TargetProxy)
    $candidate = Get-ChildItem -LiteralPath $root -Directory -Force |
        Where-Object {
            $_.Name -cmatch $leafPattern -and
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'report.json') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'binding.json') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'commit.json') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'runtime-events.jsonl') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'visible-gui-attestation.json') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'visible-gui-signing-request.json') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'visible-gui.png') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'post-run-receipt.json') -PathType Leaf)
        } | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if ($null -eq $candidate) { return $null }
    return Join-Path $candidate.FullName 'report.json'
}

function Write-NewUtf8File([string]$Path, [string]$Content) {
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Content)
    $null = Write-NewBytesFile $Path $bytes
    return $bytes
}

function Write-NewBytesFile([string]$Path, [byte[]]$Bytes) {
    $stream = [System.IO.File]::Open(
        $Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    return $Bytes
}

function Write-ImmutableReportAndBinding(
        [string]$RunDirectory,
        [System.Collections.IDictionary]$Report,
        [System.Collections.IDictionary]$Current) {
    $reportPath = Join-Path $RunDirectory 'report.json'
    $bindingPath = Join-Path $RunDirectory 'binding.json'
    $reportBytes = Write-NewUtf8File $reportPath ($Report | ConvertTo-Json -Depth 6 -Compress)
    $reportSha = Get-BytesSha256 $reportBytes
    $binding = [ordered]@{
        schema = $bindingSchema
        report_schema = $reportSchema
        report_generated_at = [string]$Report.generated_at
        report_sha256 = $reportSha
        source_mode = 'EXECUTED_REAL_FABRIC_GUI'
        source_proxy = $SourceProxy
        target_proxy = $TargetProxy
        visible_gui_trust_root_sha256 = [string]$Report.operator_visible_gui_trust_root_sha256
        visible_gui_attestation_sha256 = [string]$Report.operator_visible_gui_attestation_json_sha256
        visible_gui_attestation_size_bytes = [long]$Report.operator_visible_gui_attestation_json_size_bytes
        visible_gui_screenshot_sha256 = [string]$Report.operator_visible_gui_screenshot_sha256
        visible_gui_screenshot_size_bytes = [long]$Report.operator_visible_gui_screenshot_size_bytes
        visible_gui_screenshot_width = [int]$Report.operator_visible_gui_screenshot_width
        visible_gui_screenshot_height = [int]$Report.operator_visible_gui_screenshot_height
        visible_gui_screenshot_decoded_pixel_sha256 = [string]$Report.operator_visible_gui_screenshot_decoded_pixel_sha256
        runtime_ledger_sha256 = [string]$Report.runtime_ledger_sha256
        runtime_ledger_size_bytes = [long]$Report.runtime_ledger_size_bytes
        runtime_ledger_event_count = [int]$Report.runtime_ledger_event_count
        runtime_ledger_head_sha256 = [string]$Report.runtime_ledger_head_sha256
        runtime_ledger_supervisor_seal_sha256 = [string]$Report.runtime_ledger_supervisor_seal_sha256
        release_bundle_manifest_sha256 = [string]$Report.release_bundle_manifest_sha256
        release_bundle_fabric_jar_sha256 = [string]$Report.release_bundle_fabric_jar_sha256
        passed = $true
    }
    foreach ($name in @($Current.Keys)) { $binding[$name] = $Current[$name] }
    $bindingBytes = Write-NewUtf8File $bindingPath ($binding | ConvertTo-Json -Depth 6 -Compress)
    $bindingSha = Get-BytesSha256 $bindingBytes
    return [pscustomobject]@{
        report_path = $reportPath
        report_bytes = $reportBytes
        report_sha256 = $reportSha
        report_size_bytes = [long]$reportBytes.Length
        binding_path = $bindingPath
        binding_bytes = $bindingBytes
        binding_sha256 = $bindingSha
        binding_size_bytes = [long]$bindingBytes.Length
        binding = $binding
    }
}

function Write-FederationCommit(
        [string]$RunDirectory,
        [System.Collections.IDictionary]$Report,
        [object]$ImmutableDocuments,
        [object]$PostRunReceiptEvidence,
        [object]$PostRunReceipt) {
    $commitPath = Join-Path $RunDirectory 'commit.json'
    $commit = [ordered]@{
        schema = $commitSchema
        report_schema = $reportSchema
        binding_schema = $bindingSchema
        generated_at = [string]$Report.generated_at
        report_sha256 = [string]$ImmutableDocuments.report_sha256
        binding_sha256 = [string]$ImmutableDocuments.binding_sha256
        visible_gui_attestation_sha256 = [string]$Report.operator_visible_gui_attestation_json_sha256
        visible_gui_screenshot_sha256 = [string]$Report.operator_visible_gui_screenshot_sha256
        runtime_ledger_sha256 = [string]$Report.runtime_ledger_sha256
        runtime_ledger_head_sha256 = [string]$Report.runtime_ledger_head_sha256
        runtime_ledger_supervisor_seal_sha256 = [string]$Report.runtime_ledger_supervisor_seal_sha256
        release_bundle_manifest_sha256 = [string]$Report.release_bundle_manifest_sha256
        release_bundle_fabric_jar_sha256 = [string]$Report.release_bundle_fabric_jar_sha256
        postrun_receipt_schema = $postRunReceiptSchema
        postrun_receipt_sha256 = [string]$PostRunReceiptEvidence.sha256
        postrun_receipt_size_bytes = [long]$PostRunReceiptEvidence.size_bytes
        postrun_trust_root_sha256 = [string]$PostRunReceipt.signer_trust_root_sha256
        postrun_signer_key_id = [string]$PostRunReceipt.signer_key_id
        postrun_operation_attempt_id = [string]$PostRunReceipt.postrun_operation_attempt_id
        postrun_challenge_nonce = [string]$PostRunReceipt.postrun_challenge_nonce
        fabric_target = $FabricTarget
        source_proxy = $SourceProxy
        target_proxy = $TargetProxy
        passed = $true
    }
    $null = Write-NewUtf8File $commitPath ($commit | ConvertTo-Json -Depth 4 -Compress)
    return $commitPath
}

function Start-FederationJavaService(
        [string]$Name,
        [string]$WorkingDirectory,
        [string]$Jar,
        [string]$MaximumHeap,
        [string[]]$ExtraArguments) {
    Assert-SmokeRunToken $runToken
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $script:TargetJavaPath
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    Set-ProcessArguments $startInfo `
        (@($runTokenJvmArgument, '-Xms128m', "-Xmx$MaximumHeap", '-jar', $Jar) + $ExtraArguments)
    $stdoutPath = Join-Path $WorkingDirectory "$Name-stdout.log"
    $stderrPath = Join-Path $WorkingDirectory "$Name-stderr.log"
    $stdoutStream = [System.IO.File]::Open(
        $stdoutPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read)
    $stderrStream = [System.IO.File]::Open(
        $stderrPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read)
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw "FABRIC_FEDERATION_GUI_SERVICE_START_FAILED: $Name" }
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdoutStream)
        $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderrStream)
        return [pscustomobject]@{
            Name = $Name
            Process = $process
            Pid = [int]$process.Id
            WorkingDirectory = $WorkingDirectory
            RunToken = $runToken
            StdoutPath = $stdoutPath
            StderrPath = $stderrPath
            StdoutStream = $stdoutStream
            StderrStream = $stderrStream
            StdoutTask = $stdoutTask
            StderrTask = $stderrTask
        }
    } catch {
        $stdoutStream.Dispose()
        $stderrStream.Dispose()
        $process.Dispose()
        throw
    }
}

function Send-ServiceCommand($Service, [string]$Command) {
    if ($null -eq $Service -or $Service.Process.HasExited) {
        throw 'FABRIC_FEDERATION_GUI_SERVICE_COMMAND_TARGET_EXITED'
    }
    $Service.Process.StandardInput.WriteLine($Command)
    $Service.Process.StandardInput.Flush()
}

function Get-ServiceText($Service) {
    if ($null -eq $Service) { return '' }
    $paths = [System.Collections.Generic.List[string]]::new()
    $paths.Add([string]$Service.StdoutPath)
    $paths.Add([string]$Service.StderrPath)
    foreach ($file in @(Get-ChildItem -LiteralPath $Service.WorkingDirectory -File -Filter 'proxy.log.*' -ErrorAction SilentlyContinue)) {
        $paths.Add($file.FullName)
    }
    $latest = Join-Path $Service.WorkingDirectory 'logs\latest.log'
    if (Test-Path -LiteralPath $latest -PathType Leaf) { $paths.Add($latest) }
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($path in @($paths.ToArray() | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $content = Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue
            if ($null -ne $content) { $parts.Add([string]$content) }
        }
    }
    return $parts -join [Environment]::NewLine
}

function Wait-ServiceRegex($Service, [string]$Pattern, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $content = Get-ServiceText $Service
        if ([regex]::IsMatch($content, $Pattern,
                [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)) { return }
        if ($Service.Process.HasExited) {
            throw "FABRIC_FEDERATION_GUI_SERVICE_EXITED_BEFORE_MARKER: $($Service.Name)"
        }
        Start-Sleep -Seconds 1
    }
    throw "FABRIC_FEDERATION_GUI_SERVICE_MARKER_TIMEOUT: $($Service.Name)"
}

function Get-ServiceRegexCount($Service, [string]$Pattern) {
    return [regex]::Matches(
        (Get-ServiceText $Service), $Pattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
}

function Wait-NewServiceRegex(
        $Service,
        [string]$Pattern,
        [int]$BaselineCount,
        [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Get-ServiceRegexCount $Service $Pattern) -gt $BaselineCount) { return }
        if ($Service.Process.HasExited) {
            throw "FABRIC_FEDERATION_GUI_SERVICE_EXITED_BEFORE_NEW_MARKER: $($Service.Name)"
        }
        Start-Sleep -Seconds 1
    }
    throw "FABRIC_FEDERATION_GUI_NEW_SERVICE_MARKER_TIMEOUT: $($Service.Name)"
}

function Get-SecondsUntilDeadline(
        [DateTimeOffset]$Deadline,
        [int]$MaximumSeconds,
        [string]$ExpiredError) {
    $remaining = [int][Math]::Floor(($Deadline - [DateTimeOffset]::UtcNow).TotalSeconds)
    if ($remaining -lt 1) { throw $ExpiredError }
    return [Math]::Min($MaximumSeconds, $remaining)
}

function Assert-NewPaperVerifiedSnapshot(
        $PaperService,
        [string]$PaperLogPath,
        [string]$PlayerName,
        [int]$TimeoutSeconds) {
    $pattern = 'MCAce: {0} trust=VERIFIED admission=VERIFIED risk=0 band=NORMAL' -f
        [regex]::Escape($PlayerName)
    $baseline = Get-FileRegexCount $PaperLogPath $pattern
    Send-ServiceCommand $PaperService "mcace check $PlayerName"
    Wait-NewFileRegex $PaperService $PaperLogPath $pattern $baseline $TimeoutSeconds
}

function Assert-TargetSessionStillConnected(
        $FabricClient,
        $TargetProxyService,
        $TargetPaperService,
        [string]$TargetPaperLog,
        [string]$DisconnectMarker,
        [int]$DisconnectBaseline) {
    if ($FabricClient.Process.HasExited -or $TargetProxyService.Process.HasExited -or
            $TargetPaperService.Process.HasExited) {
        throw 'FABRIC_FEDERATION_GUI_TARGET_RUNTIME_EXITED_BEFORE_OBSERVATION_EXPIRY'
    }
    if ((Get-FileLiteralCount $TargetPaperLog $DisconnectMarker) -ne $DisconnectBaseline) {
        throw 'FABRIC_FEDERATION_GUI_TARGET_SESSION_DISCONNECTED_BEFORE_OBSERVATION_EXPIRY'
    }
}

function Stop-FederationJavaService($Service, [string]$Command) {
    if ($null -eq $Service) { return }
    $process = $Service.Process
    $rootPid = [int]$Service.Pid
    try {
        if (-not $process.HasExited) {
            if (-not [string]::IsNullOrWhiteSpace($Command)) {
                try { Send-ServiceCommand $Service $Command } catch { }
            }
            if (-not $process.WaitForExit(30000)) {
                Stop-SmokeProcessTree $rootPid $Service.RunToken
                if (-not $process.HasExited) {
                    $process.Kill()
                    [void]$process.WaitForExit(10000)
                }
            }
        }
        Stop-SmokeProcessTree $rootPid $Service.RunToken
        $Service.StdoutTask.GetAwaiter().GetResult()
        $Service.StderrTask.GetAwaiter().GetResult()
    } finally {
        $Service.StdoutStream.Flush()
        $Service.StderrStream.Flush()
        $Service.StdoutStream.Dispose()
        $Service.StderrStream.Dispose()
        $process.Dispose()
    }
}

function Write-Utf8([string]$Path, [string]$Content) {
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function Set-ExactConfigProperties(
        [string]$Path,
        [System.Collections.IDictionary]$Values) {
    $resolved = Assert-DirectLocalPath $Path
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $content = [System.IO.File]::ReadAllText($resolved, $strictUtf8)
    $options = [System.Text.RegularExpressions.RegexOptions]::Multiline -bor
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    foreach ($entry in $Values.GetEnumerator()) {
        $pattern = '^[\t ]*{0}(?:(?:[\t ]*(?:=|:)[\t ]*)|[\t ]+)[^\r\n]*(?=\r?$)' -f
            [regex]::Escape([string]$entry.Key)
        if ([regex]::Matches($content, $pattern, $options).Count -ne 1) {
            throw "FABRIC_FEDERATION_GUI_PROXY_PROPERTY_COUNT_INVALID: $($entry.Key)"
        }
        $replacement = '{0}={1}' -f [string]$entry.Key, [string]$entry.Value
        $content = [regex]::Replace($content, $pattern, $replacement, $options)
    }
    [System.IO.File]::WriteAllText($resolved, $content, [System.Text.UTF8Encoding]::new($false))
    $readback = [System.IO.File]::ReadAllText($resolved, $strictUtf8)
    foreach ($entry in $Values.GetEnumerator()) {
        $exact = '^{0}={1}(?=\r?$)' -f
            [regex]::Escape([string]$entry.Key), [regex]::Escape([string]$entry.Value)
        if ([regex]::Matches($readback, $exact, $options).Count -ne 1) {
            throw "FABRIC_FEDERATION_GUI_PROXY_PROPERTY_READBACK_INVALID: $($entry.Key)"
        }
    }
}

function Write-BungeeConfiguration(
        [string]$Path,
        [int]$ProxyPort,
        [int]$PaperPort) {
    Write-Utf8 $Path @"
ip_forward: false
online_mode: false
forge_support: false
listeners:
- query_port: 25577
  motd: '&1MCAce federation GUI smoke'
  tab_list: GLOBAL_PING
  query_enabled: false
  proxy_protocol: false
  forced_hosts: {}
  ping_passthrough: false
  priorities:
  - lobby
  bind_local_address: true
  host: 127.0.0.1:$ProxyPort
  max_players: 20
  tab_size: 60
  force_default_server: true
timeout: 30000
connection_throttle: 4000
connection_throttle_limit: 3
disabled_commands: []
servers:
  lobby:
    motd: '&1MCAce federation Paper'
    address: 127.0.0.1:$PaperPort
    restricted: false
"@
}

function Initialize-ProxyRuntime(
        [string]$Side,
        [string]$Kind,
        [string]$Root,
        [int]$ProxyPort,
        [int]$PaperPort,
        [string]$VelocityServerJar,
        [string]$BungeeServerJar) {
    $plugins = New-ExclusiveOwnedDirectory (Join-Path $Root 'plugins') $Root
    if ($Kind -ceq 'VELOCITY') {
        $serverJar = Join-Path $Root 'velocity.jar'
        Copy-Item -LiteralPath $VelocityServerJar -Destination $serverJar
        Copy-Item -LiteralPath $velocityPlugin -Destination (Join-Path $plugins 'mcace.jar')
        Expand-VelocityConfiguration $serverJar (Join-Path $Root 'velocity.toml') $ProxyPort $PaperPort
        $dataDirectory = Join-Path $plugins 'mcace'
        $shutdownCommand = 'end'
    } else {
        $serverJar = Join-Path $Root 'BungeeCord.jar'
        Copy-Item -LiteralPath $BungeeServerJar -Destination $serverJar
        Copy-Item -LiteralPath $bungeePlugin -Destination (Join-Path $plugins 'mcace.jar')
        Write-BungeeConfiguration (Join-Path $Root 'config.yml') $ProxyPort $PaperPort
        $dataDirectory = Join-Path $plugins 'MCAce'
        $shutdownCommand = 'end'
    }
    return [pscustomobject]@{
        Side = $Side
        Kind = $Kind
        Root = $Root
        ServerJar = $serverJar
        DataDirectory = $dataDirectory
        ProxyPort = $ProxyPort
        PaperPort = $PaperPort
        ShutdownCommand = $shutdownCommand
    }
}

function Start-ProxyRuntime([object]$Runtime, [string]$Phase) {
    return Start-FederationJavaService `
        ("{0}-{1}-{2}" -f $Runtime.Side.ToLowerInvariant(), $Runtime.Kind.ToLowerInvariant(), $Phase) `
        $Runtime.Root $Runtime.ServerJar '512m' @()
}

function Wait-ProxyReady([object]$Runtime, $Service) {
    if ($Runtime.Kind -ceq 'VELOCITY') {
        Wait-ServiceRegex $Service 'MCAce Phase 2 handshake initialized' 150
        Wait-ServiceRegex $Service ('Listening on /127\.0\.0\.1:{0}' -f $Runtime.ProxyPort) 150
    } else {
        Wait-ServiceRegex $Service 'MCAce BungeeCord adapter enabled' 150
        Wait-ServiceRegex $Service ('Listening on /127\.0\.0\.1:{0}' -f $Runtime.ProxyPort) 150
    }
    $null = Assert-LoopbackListener $Service $Runtime.ProxyPort
}

function Get-ProxyIdentity([object]$Runtime) {
    $publicPath = Assert-DirectLocalPath (Join-Path $Runtime.DataDirectory 'identity\server-public-key.txt')
    $privatePath = Assert-DirectLocalPath (Join-Path $Runtime.DataDirectory 'identity\server-private-key.pk8')
    $publicText = (Get-Content -LiteralPath $publicPath -Raw -ErrorAction Stop).Trim()
    try { $publicBytes = [Convert]::FromBase64String($publicText) }
    catch { throw 'FABRIC_FEDERATION_GUI_PROXY_PUBLIC_KEY_INVALID' }
    if ($publicBytes.Length -lt 32 -or (Get-Item -LiteralPath $privatePath).Length -le 0L) {
        throw 'FABRIC_FEDERATION_GUI_PROXY_IDENTITY_INCOMPLETE'
    }
    return [pscustomobject]@{
        public_text = $publicText
        key_id_sha256 = Get-Sha256HexFromBytes $publicBytes
    }
}

function Configure-ProxyProduct(
        [object]$Runtime,
        [string]$NetworkId,
        [string]$BuildId) {
    $config = Assert-DirectLocalPath (Join-Path $Runtime.DataDirectory 'mcace.properties')
    # Velocity's admission contract accepts a maximum 30-second handshake
    # window.  Keep the value inside that product bound; the Computer Use
    # operator must foreground the client before capture so the single decision
    # lands inside this bounded admission phase.
    $handshakeTimeoutSeconds = [string]([Math]::Min(
        30, [Math]::Max(2, [int]$HumanTransitionTimeoutSeconds)))
    if ($Runtime.Kind -ceq 'VELOCITY') {
        Set-ExactConfigProperties $config ([ordered]@{
            'enforcement.mode' = 'MONITOR'
            'handshake.timeout.seconds' = $handshakeTimeoutSeconds
            'policy.server-id' = $NetworkId
            'policy.minecraft-versions' = [string]$fabricDescriptor.minecraft_version
            'policy.client-build-ids' = $BuildId
        })
    } else {
        Set-ExactConfigProperties $config ([ordered]@{
            'server.id' = $NetworkId
            'minecraft.version' = [string]$fabricDescriptor.minecraft_version
            'client.build-id' = $BuildId
            'handshake.timeout.seconds' = $handshakeTimeoutSeconds
            'disposition.enforcement.mode' = 'MONITOR'
        })
    }
}

function Write-FederationConfiguration(
        [object]$Runtime,
        [string]$LocalNetworkId,
        [string]$PeerNetworkId,
        [object]$PeerIdentity,
        [ValidateSet('ISSUE_TO', 'ACCEPT_FROM', 'ACCEPT_FROM,ISSUE_TO')]
        [string]$Capability) {
    if ($PeerIdentity.key_id_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]::IsNullOrWhiteSpace([string]$PeerIdentity.public_text)) {
        throw 'FABRIC_FEDERATION_GUI_FEDERATION_PEER_IDENTITY_INVALID'
    }
    Write-Utf8 (Join-Path $Runtime.DataDirectory 'federation.properties') @"
schema.version=1
enabled=true
local.network-id=$LocalNetworkId
assertion.ttl.seconds=$FederationAssertionTtlSeconds
peer.ids=$PeerNetworkId
peer.$PeerNetworkId.public-key-x509-base64=$($PeerIdentity.public_text)
peer.$PeerNetworkId.key-id-sha256=$($PeerIdentity.key_id_sha256)
peer.$PeerNetworkId.capabilities=$Capability
"@
}

function Probe-FederationReady(
        [object]$Runtime,
        $Service,
        [string]$NetworkId) {
    $pattern = 'MCAce: federation enabled=true configured=true audit=HEALTHY audit_backlog=0 ' +
        'audit_committed=[0-9]+ audit_failures=0 local={0} peers=1 pending=0 observations=0' -f
        [regex]::Escape($NetworkId)
    $baseline = Get-ServiceRegexCount $Service $pattern
    Send-ServiceCommand $Service 'mcacefederation status'
    # Proxy bootstrap and the first federation status task can take longer on a
    # loaded workstation (especially while the visible client is also starting).
    # Keep the probe bounded, but align it with the same human-transition budget
    # used by the GUI handshake instead of dropping a valid run at 30 seconds.
    $probeTimeoutSeconds = [Math]::Min(
        120, [Math]::Max(30, [int]$HumanTransitionTimeoutSeconds))
    Wait-NewServiceRegex $Service $pattern $baseline $probeTimeoutSeconds
}

function Initialize-PaperRuntime(
        [string]$Side,
        [string]$Root,
        [int]$Port,
        [string]$PaperServerJar,
        [string]$ProxyPublicKeyPath) {
    foreach ($directoryName in @('cache', 'libraries', 'versions')) {
        Copy-Item -LiteralPath (Assert-DirectLocalPath (Join-Path $preparedPaperRoot $directoryName) -Directory) `
            -Destination $Root -Recurse
    }
    $plugins = New-ExclusiveOwnedDirectory (Join-Path $Root 'plugins') $Root
    $data = New-ExclusiveOwnedDirectory (Join-Path $plugins 'MCAce') $plugins
    Copy-Item -LiteralPath $paperPlugin -Destination (Join-Path $plugins 'mcace.jar')
    Copy-Item -LiteralPath $PaperServerJar -Destination (Join-Path $Root 'paper.jar')
    Copy-Item -LiteralPath $ProxyPublicKeyPath -Destination (Join-Path $data 'proxy-public-key.txt')
    Write-Utf8 (Join-Path $Root 'eula.txt') "eula=true`n"
    Write-Utf8 (Join-Path $Root 'server.properties') `
        "online-mode=false`nserver-ip=127.0.0.1`nserver-port=$Port`nenable-query=false`nmotd=MCAce federation $Side`n"
    return [pscustomobject]@{
        Side = $Side
        Root = $Root
        Port = $Port
        ServerJar = Join-Path $Root 'paper.jar'
    }
}

function Start-PaperRuntime([object]$Runtime) {
    return Start-FederationJavaService `
        ("{0}-paper" -f $Runtime.Side.ToLowerInvariant()) $Runtime.Root $Runtime.ServerJar '1024m' @('--nogui')
}

function Wait-PaperReady([object]$Runtime, $Service) {
    Wait-ServiceRegex $Service ('Starting Minecraft server on 127\.0\.0\.1:{0}' -f $Runtime.Port) 300
    Wait-ServiceRegex $Service 'MCAce signed proxy admission channel enabled' 300
    Wait-ServiceRegex $Service 'Done \(' 300
    $null = Assert-LoopbackListener $Service $Runtime.Port
}

function Get-RunLocalRuntimeBinding(
        [object]$SourceRuntime,
        [object]$TargetRuntime,
        [object]$SourcePaperRuntime,
        [object]$TargetPaperRuntime) {
    $sourcePrepared = Get-PreparedTreeBinding $SourcePaperRuntime.Root
    $targetPrepared = Get-PreparedTreeBinding $TargetPaperRuntime.Root
    return [ordered]@{
        source_proxy_server_sha256 = Get-Sha256 (Assert-DirectLocalPath $SourceRuntime.ServerJar)
        target_proxy_server_sha256 = Get-Sha256 (Assert-DirectLocalPath $TargetRuntime.ServerJar)
        source_proxy_plugin_sha256 = Get-Sha256 (Assert-DirectLocalPath (Join-Path $SourceRuntime.Root 'plugins\mcace.jar'))
        target_proxy_plugin_sha256 = Get-Sha256 (Assert-DirectLocalPath (Join-Path $TargetRuntime.Root 'plugins\mcace.jar'))
        source_paper_server_sha256 = Get-Sha256 (Assert-DirectLocalPath $SourcePaperRuntime.ServerJar)
        target_paper_server_sha256 = Get-Sha256 (Assert-DirectLocalPath $TargetPaperRuntime.ServerJar)
        source_paper_plugin_sha256 = Get-Sha256 (Assert-DirectLocalPath (Join-Path $SourcePaperRuntime.Root 'plugins\mcace.jar'))
        target_paper_plugin_sha256 = Get-Sha256 (Assert-DirectLocalPath (Join-Path $TargetPaperRuntime.Root 'plugins\mcace.jar'))
        source_prepared_tree_sha256 = $sourcePrepared.sha256
        target_prepared_tree_sha256 = $targetPrepared.sha256
        source_prepared_file_count = [int]$sourcePrepared.file_count
        target_prepared_file_count = [int]$targetPrepared.file_count
        source_prepared_total_size = [long]$sourcePrepared.total_size
        target_prepared_total_size = [long]$targetPrepared.total_size
    }
}

function Assert-RunLocalRuntimeBinding(
        [System.Collections.IDictionary]$Actual,
        [System.Collections.IDictionary]$Current) {
    $sourceExpectedProxy = if ($SourceProxy -ceq 'VELOCITY') {
        $Current.velocity_server_sha256
    } else { $Current.bungee_server_sha256 }
    $targetExpectedProxy = if ($TargetProxy -ceq 'VELOCITY') {
        $Current.velocity_server_sha256
    } else { $Current.bungee_server_sha256 }
    $sourceExpectedPlugin = if ($SourceProxy -ceq 'VELOCITY') {
        $Current.velocity_plugin_sha256
    } else { $Current.bungee_plugin_sha256 }
    $targetExpectedPlugin = if ($TargetProxy -ceq 'VELOCITY') {
        $Current.velocity_plugin_sha256
    } else { $Current.bungee_plugin_sha256 }
    $expected = [ordered]@{
        source_proxy_server_sha256 = $sourceExpectedProxy
        target_proxy_server_sha256 = $targetExpectedProxy
        source_proxy_plugin_sha256 = $sourceExpectedPlugin
        target_proxy_plugin_sha256 = $targetExpectedPlugin
        source_paper_server_sha256 = $Current.paper_server_sha256
        target_paper_server_sha256 = $Current.paper_server_sha256
        source_paper_plugin_sha256 = $Current.paper_plugin_sha256
        target_paper_plugin_sha256 = $Current.paper_plugin_sha256
        source_prepared_tree_sha256 = $Current.paper_prepared_tree_sha256
        target_prepared_tree_sha256 = $Current.paper_prepared_tree_sha256
        source_prepared_file_count = $Current.paper_prepared_file_count
        target_prepared_file_count = $Current.paper_prepared_file_count
        source_prepared_total_size = $Current.paper_prepared_total_size
        target_prepared_total_size = $Current.paper_prepared_total_size
    }
    Assert-BindingUnchanged $expected $Actual 'FABRIC_FEDERATION_GUI_RUN_LOCAL_RUNTIME_MISMATCH'
}

function Get-FileText([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if ($null -eq $content) { return '' }
    return [string]$content
}

function Get-FileLiteralCount([string]$Path, [string]$Marker) {
    return [regex]::Matches(
        (Get-FileText $Path), [regex]::Escape($Marker),
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
}

function Get-FileRegexCount([string]$Path, [string]$Pattern) {
    return [regex]::Matches(
        (Get-FileText $Path), $Pattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant).Count
}

function Wait-NewFileRegex(
        $Service,
        [string]$Path,
        [string]$Pattern,
        [int]$BaselineCount,
        [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Get-FileRegexCount $Path $Pattern) -gt $BaselineCount) { return }
        if ($Service.Process.HasExited) {
            throw "FABRIC_FEDERATION_GUI_SERVICE_EXITED_BEFORE_NEW_FILE_REGEX: $($Service.Name)"
        }
        Start-Sleep -Milliseconds 100
    }
    throw "FABRIC_FEDERATION_GUI_NEW_FILE_REGEX_TIMEOUT: $($Service.Name)"
}

function Wait-FileLiteralCount(
        $Service,
        [string]$Path,
        [string]$Marker,
        [int]$MinimumCount,
        [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Get-FileLiteralCount $Path $Marker) -ge $MinimumCount) { return }
        if ($Service.Process.HasExited) {
            throw "FABRIC_FEDERATION_GUI_CLIENT_EXITED_BEFORE_MARKER: $Marker"
        }
        Start-Sleep -Seconds 1
    }
    throw "FABRIC_FEDERATION_GUI_CLIENT_MARKER_TIMEOUT: $Marker"
}

function Wait-FileRegexMatch(
        $Service,
        [string]$Path,
        [string]$Pattern,
        [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $match = [regex]::Match(
            (Get-FileText $Path), $Pattern,
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
        if ($match.Success) { return $match }
        if ($Service.Process.HasExited) {
            throw "FABRIC_FEDERATION_GUI_SERVICE_EXITED_BEFORE_FILE_REGEX: $($Service.Name)"
        }
        Start-Sleep -Milliseconds 100
    }
    throw "FABRIC_FEDERATION_GUI_FILE_REGEX_TIMEOUT: $($Service.Name)"
}

function Assert-ExactHumanGuiMarkers([string]$FabricLogPath) {
    foreach ($marker in $requiredHumanGuiMarkers) {
        if ((Get-FileLiteralCount $FabricLogPath $marker) -ne 1) {
            throw "FABRIC_FEDERATION_GUI_EXACT_HUMAN_MARKER_ONCE_REQUIRED: $marker"
        }
    }
}

function Assert-ProductFederationGuiContract {
    $rootClient = Assert-DirectLocalPath (Join-Path $repoRoot `
        'mcace-client-fabric\src\main\java\com\ellan\mcace\fabric\MCAceFabricClient.java')
    $modernClient = Assert-DirectLocalPath (Join-Path $repoRoot `
        'fabric-modern\src\main\java\com\ellan\mcace\fabric\MCAceFabricClient.java')
    $vaultPath = Assert-DirectLocalPath (Join-Path $repoRoot `
        'mcace-client-common\src\main\java\com\ellan\mcace\client\federation\FederationTokenVault.java')
    $federationRuntimePath = Assert-DirectLocalPath (Join-Path $repoRoot `
        'mcace-core\src\main\java\com\ellan\mcace\core\federation\FederationRuntime.java')
    $federationDocumentsPath = Assert-DirectLocalPath (Join-Path $repoRoot `
        'mcace-protocol\src\main\java\com\ellan\mcace\protocol\federation\FederationDocuments.java')
    foreach ($clientPath in @($rootClient, $modernClient)) {
        $content = Get-Content -LiteralPath $clientPath -Raw -ErrorAction Stop
        foreach ($marker in $requiredHumanGuiMarkers) {
            if ([regex]::Matches($content, [regex]::Escape($marker)).Count -ne 1) {
                throw "FABRIC_FEDERATION_GUI_PRODUCT_MARKER_CONTRACT_INVALID: $marker"
            }
        }
        foreach ($call in @(
                'federationVault.onConnectionClosed()', 'federationVault.cancelTargetClaims()',
                'federationVault.claimTargetHandshake(',
                'MCAceEnablementController.inheritedFederationFiles(',
                'federationVault.preparePresentation(',
                'federationVault.close()')) {
            if (-not $content.Contains($call)) {
                throw "FABRIC_FEDERATION_GUI_PRODUCT_LIFECYCLE_CONTRACT_MISSING: $call"
            }
        }
        # FederationTokenVault.commit is clock-bound so expiry is evaluated against the
        # caller's monotonic/UTC clock.  Match the current two-argument production call
        # without relying on whitespace or line wrapping.
        if (-not [regex]::IsMatch($content,
                'federationVault\.commit\(\s*prepared\s*,\s*Clock\.systemUTC\(\)\s*\)',
                [Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
            throw 'FABRIC_FEDERATION_GUI_PRODUCT_LIFECYCLE_CONTRACT_MISSING: federationVault.commit(prepared, Clock.systemUTC())'
        }
        # The grant path carries the connection-scoped authorization introduced by the
        # one-time visible enablement contract.  Match formatting-insensitively so a
        # legitimate multiline Java invocation is not rejected by this PowerShell gate.
        $grantCallPattern = 'candidate\.receiveFederationGrant\(\s*payload\.data\(\),\s*' +
            'federationVault,\s*authorization\.files\(\),\s*connectionAuthorization\)\s*;'
        if (-not [regex]::IsMatch($content, $grantCallPattern,
                [Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
            throw 'FABRIC_FEDERATION_GUI_PRODUCT_LIFECYCLE_CONTRACT_MISSING: connection-scoped federation grant call'
        }
        if ([regex]::IsMatch($content, '\bfederation(?:Import)?Consent\.request\s*\(')) {
            throw 'FABRIC_FEDERATION_GUI_SECOND_VISIBLE_PROMPT_CALL_FORBIDDEN'
        }
    }
    $vault = Get-Content -LiteralPath $vaultPath -Raw -ErrorAction Stop
    foreach ($contract in @(
            'public synchronized void onConnectionClosed()',
            'public synchronized void cancelTargetClaims()',
            'public synchronized Optional<TargetHandshakeClaim> claimTargetHandshake(',
            'Set<String> approvedExplicitFiles',
            # The disconnect lifecycle is intentionally split: onConnectionClosed() first
            # removes bound target claims via cancelTargetClaims(), then consumes an already
            # disconnected unclaimed grant; keep both predicates independently covered.
            'if (entry.sourceConnectionClosed)',
            'entry.sourceConnectionClosed = true',
            'if (entry.boundTargetKeyVerified)',
            'public synchronized void close()')) {
        if (-not $vault.Contains($contract)) {
            throw "FABRIC_FEDERATION_GUI_VAULT_DISCONNECT_CONTRACT_MISSING: $contract"
        }
    }
    $federationRuntime = Get-Content -LiteralPath $federationRuntimePath -Raw -ErrorAction Stop
    $federationDocuments = Get-Content -LiteralPath $federationDocumentsPath -Raw -ErrorAction Stop
    foreach ($contract in @(
            'FederationDocuments.issueConsentRequest(',
            'clock, current.assertionLifetime(), secureRandom',
            'Instant expiresAt = Instant.ofEpochMilli(verified.expiresAtEpochMs())',
            'if (!clock.instant().isBefore(entry.getValue().expiresAt()))')) {
        if (-not $federationRuntime.Contains($contract)) {
            throw "FABRIC_FEDERATION_GUI_ASSERTION_EXPIRY_CONTRACT_MISSING: $contract"
        }
    }
    foreach ($contract in @(
            'long issuedAt = clock.millis()',
            'long expiresAt = safeAdd(issuedAt, lifetimeMillis, "federation expiry overflow")')) {
        if (-not $federationDocuments.Contains($contract)) {
            throw "FABRIC_FEDERATION_GUI_ASSERTION_TIMESTAMP_CONTRACT_MISSING: $contract"
        }
    }
}

function Get-DistinctLoopbackPorts([int]$Count) {
    $ports = [System.Collections.Generic.HashSet[int]]::new()
    while ($ports.Count -lt $Count) { [void]$ports.Add((Get-FreeLoopbackPort)) }
    return @($ports)
}

function Assert-FederationRunLeaf([string]$Leaf) {
    if ($Leaf -cnotmatch '^[0-9]{8}T[0-9]{9}Z-(?:1_21_11|26_1_2|26_2)-(?:VELOCITY|BUNGEE)-to-(?:VELOCITY|BUNGEE)-[0-9a-f]{32}$') {
        throw 'FABRIC_FEDERATION_GUI_CSPRNG_RUN_LEAF_REQUIRED'
    }
}

function Assert-OwnedRunDirectory([string]$RunDirectory) {
    $root = Assert-DirectLocalPath $evidenceRunsRoot -Directory
    $run = Assert-OwnedTreeNoReparse $RunDirectory
    Assert-FederationRunLeaf ([System.IO.Path]::GetFileName($run))
    if (-not [System.IO.Path]::GetDirectoryName($run).Equals(
            $root, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'FABRIC_FEDERATION_GUI_RUN_PARENT_INVALID'
    }
    return $run
}

function Remove-OwnedRunDirectory([string]$RunDirectory) {
    if (-not (Test-Path -LiteralPath $RunDirectory -PathType Container)) { return }
    $run = Assert-OwnedRunDirectory $RunDirectory
    Remove-Item -LiteralPath $run -Recurse -Force
}

function Clear-OwnedRunForEvidence([string]$RunDirectory) {
    $run = Assert-OwnedRunDirectory $RunDirectory
    foreach ($entry in @(Get-ChildItem -LiteralPath $run -Force)) {
        $resolved = [System.IO.Path]::GetFullPath($entry.FullName)
        if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'FABRIC_FEDERATION_GUI_REPARSE_DIAGNOSTIC_REJECTED'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
    if (@(Get-ChildItem -LiteralPath $run -Force).Count -ne 0) {
        throw 'FABRIC_FEDERATION_GUI_RAW_RUN_CONTENT_RESIDUE'
    }
}

$script:ServerAssets = Resolve-FederationServerAssets
$preparedPaperRoot = [string]$script:ServerAssets.prepared_root
$repoInputPrefix = [System.IO.Path]::GetFullPath($repoRoot).TrimEnd('\') + '\'
$approvedVisibleGuiTrustRootSha256 = Get-ApprovedReleaseSignerPin `
    'MCACE_RELEASE_APPROVED_FEDERATION_GUI_TRUST_ROOT_SHA256' 'GUI'
$approvedPostRunTrustRootSha256 = Get-ApprovedReleaseSignerPin `
    'MCACE_RELEASE_APPROVED_FEDERATION_POSTRUN_TRUST_ROOT_SHA256' 'POSTRUN'
if ($approvedVisibleGuiTrustRootSha256 -ceq $approvedPostRunTrustRootSha256) {
    throw 'FABRIC_FEDERATION_GUI_APPROVED_SIGNER_PINS_MUST_DIFFER'
}
$visibleGuiTrustRootFull = Assert-DirectLocalPath $VisibleGuiTrustRootPath
if ($visibleGuiTrustRootFull.StartsWith($repoInputPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'FABRIC_FEDERATION_GUI_TRUST_ROOT_MUST_BE_OUT_OF_BAND'
}
$visibleGuiTrustRootEvidence = Open-LockedEvidence $visibleGuiTrustRootFull
$validatedVisibleGuiTrustRoot = Assert-VisibleGuiTrustRoot $visibleGuiTrustRootEvidence `
    $ExpectedVisibleGuiTrustRootSha256 $approvedVisibleGuiTrustRootSha256
$postRunTrustRootFull = Assert-DirectLocalPath $PostRunSupervisorTrustRootPath
if ($postRunTrustRootFull.StartsWith($repoInputPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'FABRIC_FEDERATION_GUI_POSTRUN_TRUST_ROOT_MUST_BE_OUT_OF_BAND'
}
$postRunTrustRootEvidence = Open-LockedEvidence $postRunTrustRootFull
$validatedPostRunTrustRoot = Assert-PostRunSupervisorTrustRoot $postRunTrustRootEvidence `
    $ExpectedPostRunSupervisorTrustRootSha256 $approvedPostRunTrustRootSha256
Assert-DistinctFederationSignerRoots $validatedVisibleGuiTrustRoot $validatedPostRunTrustRoot

if ($ReportOnly) {
    try {
        $current = Get-CurrentBinding
        Assert-ReportOnlyExpectedBinding $current
        $releaseBundleBinding = Get-ReleaseBundleTargetBinding `
            $ReleaseBundleRoot ([string]$current.source_commit) ([string]$current.source_commit) `
            $FabricTarget $SourceProxy $TargetProxy
        if ($releaseBundleBinding.fabric_jar_sha256 -cne [string]$current.fabric_artifact_sha256) {
            throw 'FABRIC_FEDERATION_GUI_FINAL_RELEASE_JAR_RUNTIME_HASH_MISMATCH'
        }
        $latest = Get-LatestCompleteEvidenceReport
        if ($null -eq $latest) {
            throw 'FABRIC_FEDERATION_GUI_TARGET_BOUND_V5_EVIDENCE_SET_REQUIRED'
        }
        $null = Assert-EvidenceSet $latest $current $SourceProxy $TargetProxy `
            $visibleGuiTrustRootEvidence $postRunTrustRootEvidence $releaseBundleBinding `
            $approvedVisibleGuiTrustRootSha256 $approvedPostRunTrustRootSha256
        Write-Output "FABRIC_FEDERATION_GUI_HANDOFF_PASS|report-only|target=$FabricTarget|source=$SourceProxy|target_proxy=$TargetProxy"
        exit 0
    } finally {
        $postRunTrustRootEvidence.stream.Dispose()
        $visibleGuiTrustRootEvidence.stream.Dispose()
    }
}

$visibleGuiSigningRequestOutput = Resolve-ExternalEvidenceOutputLeaf `
    $VisibleGuiSigningRequestPath 'GUI_SIGNING_REQUEST'
$visibleGuiAttestationInput = Resolve-ExternalEvidenceOutputLeaf `
    $VisibleGuiAttestationPath 'ATTESTATION'
$visibleGuiScreenshotInput = Resolve-ExternalEvidenceOutputLeaf `
    $VisibleGuiScreenshotPath 'SCREENSHOT'
$postRunSigningRequestOutput = Resolve-ExternalEvidenceOutputLeaf `
    $PostRunSigningRequestPath 'POSTRUN_SIGNING_REQUEST'
$postRunReceiptInput = Resolve-ExternalEvidenceOutputLeaf `
    $PostRunReceiptPath 'POSTRUN_RECEIPT'
$externalEvidencePaths = @($visibleGuiSigningRequestOutput, $visibleGuiAttestationInput,
    $visibleGuiScreenshotInput,
    $postRunSigningRequestOutput, $postRunReceiptInput)
if (@($externalEvidencePaths | Select-Object -Unique).Count -ne $externalEvidencePaths.Count) {
    throw 'FABRIC_FEDERATION_GUI_EXTERNAL_EVIDENCE_PATHS_MUST_DIFFER'
}
if (@($externalEvidencePaths | Where-Object { Test-Path -LiteralPath $_ }).Count -ne 0) {
    throw 'FABRIC_FEDERATION_GUI_EXTERNAL_EVIDENCE_MUST_BE_CREATED_DURING_RUN'
}
foreach ($externalInput in $externalEvidencePaths) {
    if ([System.IO.Path]::GetFullPath($externalInput).StartsWith(
            $repoInputPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'FABRIC_FEDERATION_GUI_EXTERNAL_EVIDENCE_INSIDE_SOURCE_TREE_REJECTED'
    }
}
if ($requiredHumanGuiMarkers.Count -ne 7) {
    throw 'FABRIC_FEDERATION_GUI_ENABLEMENT_MARKER_CONTRACT_REQUIRED'
}

Assert-ProductFederationGuiContract
$script:RootJava = Resolve-RootJava21
$script:TargetJava = Resolve-TargetJava
$script:RootJavaPath = $script:RootJava.path
$script:TargetJavaPath = $script:TargetJava.path
$script:OfflineGradle = Resolve-OfflineGradle961

$repoRoot = Assert-DirectLocalPath $repoRoot -Directory
$buildRoot = Initialize-SafeOwnedDirectory (Join-Path $repoRoot 'build') $repoRoot
$evidenceRoot = Initialize-SafeOwnedDirectory $evidenceRoot $buildRoot
$evidenceRunsRoot = Initialize-SafeOwnedDirectory $evidenceRunsRoot $evidenceRoot
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
$runToken = New-SmokeRunToken
Assert-SmokeRunToken $runToken
$runAttemptId = New-CryptographicHex 16
$guiAttemptId = New-CryptographicHex 16
$guiChallengeNonce = New-CryptographicHex 32
$guiChallengeIssuedAt = [DateTimeOffset]::MinValue
$sourceConnectionId = New-CryptographicHex 16
$targetConnectionId = New-CryptographicHex 16
$federationSessionId = New-CryptographicHex 16
$sourceSecondOperationAttemptId = New-CryptographicHex 16
$targetInheritedOperationAttemptId = New-CryptographicHex 16
$runTokenJvmArgument = "-Dmcace.smoke.run-token=$runToken"
$fabricSmokeBuildId = "platform-smoke-$runId"
$runLeaf = '{0}-{1}-{2}-to-{3}-{4}' -f
    $runId, $FabricTarget.Replace('.', '_'), $SourceProxy, $TargetProxy, $runToken
Assert-FederationRunLeaf $runLeaf
$runRoot = Join-Path $evidenceRunsRoot $runLeaf
$runRootPrefix = [System.IO.Path]::GetFullPath($runRoot).TrimEnd('\') + '\'
foreach ($externalInput in @($visibleGuiSigningRequestOutput, $visibleGuiAttestationInput,
        $visibleGuiScreenshotInput)) {
    if ([System.IO.Path]::GetFullPath($externalInput).StartsWith(
            $runRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'FABRIC_FEDERATION_GUI_EXTERNAL_EVIDENCE_INSIDE_MUTABLE_RUN_REJECTED'
    }
}

try {
$preBuildInput = Get-ImmutableInputBinding
$releaseBundleBinding = Get-ReleaseBundleTargetBinding `
    $releaseBundleRuntimeRoot ([string]$preBuildInput.source_commit) `
    ([string]$preBuildInput.source_commit) $FabricTarget $SourceProxy $TargetProxy
$fabricSmokeBuildId = [string]$releaseBundleBinding.client_build_id
$protectedFabricSha256 = [string]$releaseBundleBinding.fabric_jar_sha256
$smokeBuildProperties = @(
    '-PmcaceSmokeArtifactMode=true',
    "-PmcaceClientBuildId=$fabricSmokeBuildId",
    "-PmcaceSmokeRunToken=$runToken",
    "-PmcaceSmokeRuntimeArtifactPath=$fabricArtifactJar",
    "-PmcaceSmokeExpectedArtifactSha256=$protectedFabricSha256",
    "-PmcaceSmokeConsentTimeoutSeconds=$([Math]::Min(300, [Math]::Max(30, [int]$HumanTransitionTimeoutSeconds)))"
)
if ([int]$fabricDescriptor.java_major -eq 25) {
    # The root stage task evaluates the legacy 1.21.11 Fabric project as part of
    # the shared dependency graph.  Its artifact-mode contract only accepts a
    # legacy-valid platform-smoke ID or a 1.21.11 release ID; passing the target
    # 26.x release ID here makes configuration fail before the modern verifier
    # runs.  Keep the stage invocation scoped to a synthetic smoke identity,
    # then pass the protected target release identity to fabric-modern below.
    $rootStageProperties = @(
        '-PmcaceSmokeArtifactMode=true',
        "-PmcaceClientBuildId=platform-smoke-$runId",
        "-PmcaceSmokeRunToken=$runToken"
    )
    Invoke-PinnedOfflineGradle $script:RootJavaPath $repoRoot @(':stageModernFabricDeps') `
        $rootStageProperties $true 'FABRIC_FEDERATION_GUI_ROOT_JDK21_BUILD_FAILED'
    $modernProperties = @($smokeBuildProperties) + @(
        "-PmcaceRootDepsDir=$stagedModernDependencies",
        "-PmcaceProductVersion=$fabricArtifactVersion"
    )
    $verificationProperties = $modernProperties
} else {
    $verificationProperties = $smokeBuildProperties
}
Invoke-PinnedOfflineGradle $script:TargetJavaPath ([string]$fabricDescriptor.gradle_project_directory) `
    @([string]$fabricDescriptor.verify_task) $verificationProperties $false `
    'FABRIC_FEDERATION_GUI_FABRIC_ARTIFACT_VERIFY_FAILED'

$currentBinding = Get-CurrentBinding
$postBuildInput = Get-ImmutableInputBinding
Assert-BindingUnchanged $preBuildInput $postBuildInput 'FABRIC_FEDERATION_GUI_IMMUTABLE_INPUT_CHANGED_DURING_BUILD'
if ([string]$currentBinding.fabric_build_id -cne $fabricSmokeBuildId -or
        $releaseBundleBinding.fabric_jar_sha256 -cne [string]$currentBinding.fabric_artifact_sha256) {
    throw 'FABRIC_FEDERATION_GUI_FINAL_RELEASE_JAR_RUNTIME_HASH_MISMATCH'
}
if ($releaseBundleBinding.paper_jar_sha256 -cne [string]$currentBinding.paper_plugin_sha256 -or
        ($SourceProxy -ceq 'VELOCITY' -and
            $releaseBundleBinding.source_proxy_jar_sha256 -cne [string]$currentBinding.velocity_plugin_sha256) -or
        ($SourceProxy -ceq 'BUNGEE' -and
            $releaseBundleBinding.source_proxy_jar_sha256 -cne [string]$currentBinding.bungee_plugin_sha256) -or
        ($TargetProxy -ceq 'VELOCITY' -and
            $releaseBundleBinding.target_proxy_jar_sha256 -cne [string]$currentBinding.velocity_plugin_sha256) -or
        ($TargetProxy -ceq 'BUNGEE' -and
            $releaseBundleBinding.target_proxy_jar_sha256 -cne [string]$currentBinding.bungee_plugin_sha256)) {
    throw 'FABRIC_FEDERATION_GUI_FINAL_RELEASE_SERVER_RUNTIME_HASH_MISMATCH'
}
foreach ($entry in @(
        @($velocityPlugin, 'com/ellan/mcace/velocity/MCAceVelocityChannels.class'),
        @($bungeePlugin, 'com/ellan/mcace/bungeecord/BungeeMCAceChannels.class'))) {
    if (-not (Test-JarEntry $entry[0] $entry[1])) {
        throw 'FABRIC_FEDERATION_GUI_PROXY_TRANSPORT_CLASS_REQUIRED'
    }
}
$fabricExpectedArtifactMarker =
    "MCACE_FABRIC_ARTIFACT_LOADED version=$fabricArtifactVersion build_id=$($currentBinding.fabric_build_id)" +
    " code_source_sha256=$($currentBinding.fabric_artifact_sha256)"

$velocityServerJar = Get-VerifiedArtifact $script:ServerAssets.velocity
$bungeeServerJar = Get-VerifiedBungeeArtifact $script:ServerAssets.bungee
$paperServerJar = Get-VerifiedArtifact $script:ServerAssets.paper
} catch {
    try { Stop-RunTokenJavaProcesses $runToken } catch { }
    $postRunTrustRootEvidence.stream.Dispose()
    $visibleGuiTrustRootEvidence.stream.Dispose()
    throw
}

$sourceService = $null
$targetService = $null
$sourcePaperService = $null
$targetPaperService = $null
$fabricClient = $null
$sourcePaperRuntime = $null
$targetPaperRuntime = $null
$sourceRuntime = $null
$targetRuntime = $null
$allPorts = @()
$runRootCreated = $false
$runLocalBefore = $null
$failure = $null
$runtimeAssertionsComplete = $false
$clientShutdownCompleted = $false
$sourceLocalAuthVerified = $false
$sourcePaperAdmissionVerified = $false
$sourceGrantReadyObserved = $false
$sourceDisconnectedBeforeTargetAuth = $false
$targetLocalAuthVerified = $false
$targetPaperAdmissionVerified = $false
$targetObservationRecorded = $false
$targetSubjectBound = $false
$targetObservationCountOne = $false
$targetObservationOneBeforeExpiry = $false
$targetSessionConnectedThroughExpiry = $false
$observationExpired = $false
$targetObservationZero = $false
$localStateUnchanged = $false
$presentationSent = $false
$fabricClientStartedAt = [DateTimeOffset]::MinValue
$guiPromptRenderedAt = [DateTimeOffset]::MinValue
$enablementAcceptedAt = [DateTimeOffset]::MinValue
$visibleGuiSigningRequestEvidence = $null
$validatedVisibleGuiSigningRequest = $null
$visibleGuiSigningRequestExpected = $null
$visibleGuiAttestationEvidence = $null
$visibleGuiScreenshotEvidence = $null
$validatedVisibleGuiAttestation = $null
$postRunReceiptEvidence = $null
$validatedPostRunReceipt = $null
$sourceSecondAssertionRuntimeRequested = $false
$sourceSecondAssertionFabricRejected = $false
$sourceSecondAssertionFabricRejectionCountDelta = -1
$sourceSecondAssertionGrantReadyDelta = -1
$targetInheritedExportRuntimeRequested = $false
$targetInheritedExportFabricRejected = $false
$targetInheritedExportFabricRejectionCountDelta = -1
$targetInheritedExportGrantReadyDelta = -1
$runtimeLedger = $null
$runtimeLedgerEvidenceBytes = $null
$validatedRuntimeLedger = $null
$runtimeLedgerSeal = ''
$sourceSubjectCommitmentSha256 = '0' * 64
$targetSubjectCommitmentSha256 = '0' * 64

try {
    # Create mutable run state only after the pinned build and artifact verification succeeds so a
    # build/preflight failure cannot strand a half-created run leaf outside the cleanup boundary.
    $runRoot = New-ExclusiveOwnedDirectory $runRoot $evidenceRunsRoot
    $runRootCreated = $true
    $guiChallengeIssuedAt = [DateTimeOffset]::UtcNow
    $runtimeLedger = New-RuntimeLedger (Join-Path $runRoot 'runtime-events.jsonl') `
        $runAttemptId ([string]$currentBinding.source_commit) $FabricTarget
    $supervisorMarker = "run-attempt=$runAttemptId;challenge=$guiChallengeNonce"
    $null = Add-RuntimeLedgerEvent $runtimeLedger 'RUN_STARTED' '' 'SUPERVISOR' $PID `
        ([string]$runtimeLedger.supervisor_process_started_at) '' '' '' ('0' * 64) `
        (Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($supervisorMarker)))
    $sourceProxyRoot = New-ExclusiveOwnedDirectory (Join-Path $runRoot 'source-proxy') $runRoot
    $targetProxyRoot = New-ExclusiveOwnedDirectory (Join-Path $runRoot 'target-proxy') $runRoot
    $sourcePaperRoot = New-ExclusiveOwnedDirectory (Join-Path $runRoot 'source-paper') $runRoot
    $targetPaperRoot = New-ExclusiveOwnedDirectory (Join-Path $runRoot 'target-paper') $runRoot
    $fabricRoot = New-ExclusiveOwnedDirectory (Join-Path $runRoot 'fabric-client') $runRoot

    $ports = Get-DistinctLoopbackPorts 4
    $sourceProxyPort = [int]$ports[0]
    $targetProxyPort = [int]$ports[1]
    $sourcePaperPort = [int]$ports[2]
    $targetPaperPort = [int]$ports[3]
    $allPorts = @($sourceProxyPort, $targetProxyPort, $sourcePaperPort, $targetPaperPort)

    $sourceRuntime = Initialize-ProxyRuntime `
        'SOURCE' $SourceProxy $sourceProxyRoot $sourceProxyPort $sourcePaperPort `
        $velocityServerJar $bungeeServerJar
    $targetRuntime = Initialize-ProxyRuntime `
        'TARGET' $TargetProxy $targetProxyRoot $targetProxyPort $targetPaperPort `
        $velocityServerJar $bungeeServerJar

    # Bootstrap both isolated proxies only far enough to create their persistent identities and
    # strict default product/federation files. No client connects during this phase.
    $sourceService = Start-ProxyRuntime $sourceRuntime 'bootstrap'
    Wait-ProxyReady $sourceRuntime $sourceService
    $targetService = Start-ProxyRuntime $targetRuntime 'bootstrap'
    Wait-ProxyReady $targetRuntime $targetService
    $sourceIdentity = Get-ProxyIdentity $sourceRuntime
    $targetIdentity = Get-ProxyIdentity $targetRuntime
    Stop-FederationJavaService $sourceService $sourceRuntime.ShutdownCommand
    $sourceService = $null
    Stop-FederationJavaService $targetService $targetRuntime.ShutdownCommand
    $targetService = $null

    Configure-ProxyProduct $sourceRuntime 'mcace-source' $fabricSmokeBuildId
    Configure-ProxyProduct $targetRuntime 'mcace-target' $fabricSmokeBuildId
    Write-FederationConfiguration `
        $sourceRuntime 'mcace-source' 'mcace-target' $targetIdentity 'ISSUE_TO'
    Write-FederationConfiguration `
        $targetRuntime 'mcace-target' 'mcace-source' $sourceIdentity 'ACCEPT_FROM,ISSUE_TO'

    $sourceService = Start-ProxyRuntime $sourceRuntime 'active'
    Wait-ProxyReady $sourceRuntime $sourceService
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'PROCESS_STARTED' '' 'SOURCE_PROXY' `
        $sourceService.Process 'mcace-target' $sourceConnectionId $federationSessionId `
        ('0' * 64) 'source proxy active process ready'
    $targetService = Start-ProxyRuntime $targetRuntime 'active'
    Wait-ProxyReady $targetRuntime $targetService
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'PROCESS_STARTED' '' 'TARGET_PROXY' `
        $targetService.Process 'mcace-source' $targetConnectionId $federationSessionId `
        ('0' * 64) 'target proxy active process ready'
    Probe-FederationReady $sourceRuntime $sourceService 'mcace-source'
    Probe-FederationReady $targetRuntime $targetService 'mcace-target'

    $sourcePinPath = Assert-DirectLocalPath `
        (Join-Path $sourceRuntime.DataDirectory 'identity\server-public-key.txt')
    $targetPinPath = Assert-DirectLocalPath `
        (Join-Path $targetRuntime.DataDirectory 'identity\server-public-key.txt')
    $sourcePaperRuntime = Initialize-PaperRuntime `
        'source' $sourcePaperRoot $sourcePaperPort $paperServerJar $sourcePinPath
    $targetPaperRuntime = Initialize-PaperRuntime `
        'target' $targetPaperRoot $targetPaperPort $paperServerJar $targetPinPath
    $runLocalBefore = Get-RunLocalRuntimeBinding `
        $sourceRuntime $targetRuntime $sourcePaperRuntime $targetPaperRuntime
    Assert-RunLocalRuntimeBinding $runLocalBefore $currentBinding

    $sourcePaperService = Start-PaperRuntime $sourcePaperRuntime
    Wait-PaperReady $sourcePaperRuntime $sourcePaperService
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'PROCESS_STARTED' '' 'SOURCE_PAPER' `
        $sourcePaperService.Process 'mcace-source' $sourceConnectionId $federationSessionId `
        ('0' * 64) 'source paper active process ready'
    $targetPaperService = Start-PaperRuntime $targetPaperRuntime
    Wait-PaperReady $targetPaperRuntime $targetPaperService
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'PROCESS_STARTED' '' 'TARGET_PAPER' `
        $targetPaperService.Process 'mcace-target' $targetConnectionId $federationSessionId `
        ('0' * 64) 'target paper active process ready'

    $fabricConfig = New-ExclusiveOwnedDirectory (Join-Path $fabricRoot 'config') $fabricRoot
    $fabricMCAceConfig = New-ExclusiveOwnedDirectory (Join-Path $fabricConfig 'mcace') $fabricConfig
    $null = New-ExclusiveOwnedDirectory (Join-Path $fabricRoot 'mods') $fabricRoot
    $sourceAddress = "127.0.0.1:$sourceProxyPort"
    $targetAddress = "127.0.0.1:$targetProxyPort"
    $sourcePinValue = (Get-Content -LiteralPath $sourcePinPath -Raw -ErrorAction Stop).Trim()
    $targetPinValue = (Get-Content -LiteralPath $targetPinPath -Raw -ErrorAction Stop).Trim()
    $sourcePropertyAddress = $sourceAddress.Replace(':', '\:')
    $targetPropertyAddress = $targetAddress.Replace(':', '\:')
    Write-Utf8 (Join-Path $fabricMCAceConfig 'server-keys.properties') `
        "$sourcePropertyAddress=$sourcePinValue`n$targetPropertyAddress=$targetPinValue`n"
    Write-Utf8 (Join-Path $fabricRoot 'options.txt') "fov:0.5`nrenderDistance:8`n"

    Write-Host ''
    Write-Host "SOURCE HUMAN PHASE ($sourceAddress): approve the single visible connection-level Enable MCAce prompt exactly once."
    Write-Host 'This runner does not click, focus, type into, or automate the Fabric window.'
    Write-Host "GUI exchange paths: screenshot=$visibleGuiScreenshotInput request=$visibleGuiSigningRequestOutput receipt=$visibleGuiAttestationInput"
    Write-Host 'Capture the real prompt PNG first. The runner then publishes the canonical signing request; accept only after the signed receipt verifies.'
    $fabricClientStartedAt = [DateTimeOffset]::UtcNow
    $fabricClient = Start-FabricReleaseClient `
        $fabricRoot $sourceAddress $true ([string]$currentBinding.fabric_artifact_sha256)
    $fabricClientProcessStartedAt = Get-ProcessStartTimeString $fabricClient.Process
    Write-Host "Fabric process binding: pid=$($fabricClient.Process.Id) started_at=$fabricClientProcessStartedAt source_commit=$($currentBinding.source_commit) fabric_target=$FabricTarget final_fabric_jar_sha256=$($currentBinding.fabric_artifact_sha256)"
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'PROCESS_STARTED' '' 'FABRIC_CLIENT' `
        $fabricClient.Process 'mcace-source' $sourceConnectionId $federationSessionId `
        ('0' * 64) $fabricExpectedArtifactMarker
    $fabricLog = Join-Path $fabricRoot 'logs\latest.log'
    Wait-FileLiteralCount $fabricClient $fabricLog $fabricExpectedArtifactMarker 1 300
    Assert-FabricArtifactMarker $fabricLog $fabricExpectedArtifactMarker
    Wait-FileLiteralCount $fabricClient $fabricLog 'MCAce Fabric client initialized' 1 300
    # The connection-level policy is presented before the client can send its
    # first authenticated hello.  Capture and approve that single visible prompt
    # first; waiting for an authenticated session here would deadlock the real
    # protocol because authentication is enabled by this decision.
    Wait-FileLiteralCount $fabricClient $fabricLog $requiredHumanGuiMarkers[0] 1 30
    Wait-FileLiteralCount $fabricClient $fabricLog $requiredHumanGuiMarkers[1] 1 30
    $guiPromptRenderedAt = [DateTimeOffset]::UtcNow
    Wait-ExternalEvidenceLeaf $visibleGuiScreenshotInput $HumanTransitionTimeoutSeconds 'SCREENSHOT'
    $visibleGuiScreenshotEvidence = Open-LockedBinaryEvidence $visibleGuiScreenshotInput
    $visibleGuiPng = Assert-PngEvidence $visibleGuiScreenshotEvidence.bytes
    $requestPathBinding = Get-CanonicalExchangePathBinding $visibleGuiSigningRequestOutput
    $screenshotPathBinding = Get-CanonicalExchangePathBinding $visibleGuiScreenshotInput
    $attestationPathBinding = Get-CanonicalExchangePathBinding $visibleGuiAttestationInput
    if ($requestPathBinding.canonicalization -cne $screenshotPathBinding.canonicalization -or
            $requestPathBinding.canonicalization -cne $attestationPathBinding.canonicalization) {
        throw 'FABRIC_FEDERATION_GUI_EXCHANGE_PATH_CANONICALIZATION_MISMATCH'
    }
    $guiRequestExpiresAt = $guiPromptRenderedAt.AddSeconds(
        [Math]::Min(180, $HumanTransitionTimeoutSeconds * 2))
    $challengeExpiryUpper = $guiChallengeIssuedAt.AddMinutes(15)
    if ($challengeExpiryUpper -lt $guiRequestExpiresAt) {
        $guiRequestExpiresAt = $challengeExpiryUpper
    }
    if ($guiRequestExpiresAt -le [DateTimeOffset]::UtcNow) {
        throw 'FABRIC_FEDERATION_GUI_SIGNING_REQUEST_EXPIRED_BEFORE_PUBLICATION'
    }
    $visibleGuiSigningRequestExpected = [ordered]@{
        schema = $visibleGuiSigningRequestSchema
        domain = $visibleGuiSigningRequestDomain
        artifact_class = $visibleGuiSigningRequestArtifactClass
        source_mode = $visibleGuiSigningRequestSourceMode
        attestation_schema = $visibleGuiAttestationSchema
        attestation_artifact_class = $visibleGuiAttestationArtifactClass
        attestation_source_mode = $visibleGuiAttestationSourceMode
        attestation_tool = 'computer-use'
        attestation_signing_domain = $visibleGuiAttestationSigningDomain
        attestation_payload_format = 'LF_KEY_EQUALS_VALUE_UTF8_FINAL_LF_V1'
        attestation_property_order_csv = $visibleGuiAttestationPropertyNames -join ','
        attestation_required_assertions = 'prompt_challenge_visible=true,operator_attested_visible_session=true,operator_attested_no_headless_or_synthetic_input=true'
        attestation_publish_mode = 'ATOMIC_CREATE_NEW_COMPLETE_JSON_THEN_CLOSE_V1'
        attestation_test_fixture = $false
        source_commit = [string]$currentBinding.source_commit
        artifact_source_commit = [string]$releaseBundleBinding.artifact_source_commit
        product_version = [string]$releaseBundleBinding.product_version
        fabric_target = $FabricTarget
        source_proxy = $SourceProxy
        target_proxy = $TargetProxy
        release_bundle_manifest_sha256 = [string]$releaseBundleBinding.manifest_sha256
        final_fabric_jar_file = [string]$releaseBundleBinding.fabric_jar_file
        final_fabric_jar_sha256 = [string]$releaseBundleBinding.fabric_jar_sha256
        final_fabric_jar_size_bytes = [long]$releaseBundleBinding.fabric_jar_size_bytes
        client_build_id = [string]$releaseBundleBinding.client_build_id
        run_attempt_id = $runAttemptId
        gui_attempt_id = $guiAttemptId
        challenge_nonce = $guiChallengeNonce
        challenge_issued_at = $guiChallengeIssuedAt.ToUniversalTime().ToString('o')
        prompt_rendered_at = $guiPromptRenderedAt.ToUniversalTime().ToString('o')
        request_created_at = [DateTimeOffset]::UtcNow.ToUniversalTime().ToString('o')
        expires_at = $guiRequestExpiresAt.ToUniversalTime().ToString('o')
        client_process_id = [int]$fabricClient.Process.Id
        client_process_started_at = $fabricClientProcessStartedAt
        path_canonicalization = [string]$requestPathBinding.canonicalization
        signing_request_file = [IO.Path]::GetFileName($visibleGuiSigningRequestOutput)
        signing_request_path_sha256 = [string]$requestPathBinding.sha256
        screenshot_file = [IO.Path]::GetFileName($visibleGuiScreenshotInput)
        screenshot_path_sha256 = [string]$screenshotPathBinding.sha256
        screenshot_freeze_mode = 'PRECLICK_FILESHARE_READ_LOCK_UNTIL_ACCEPT_V1'
        screenshot_sha256 = [string]$visibleGuiScreenshotEvidence.sha256
        screenshot_size_bytes = [long]$visibleGuiScreenshotEvidence.size_bytes
        screenshot_width = [int]$visibleGuiPng.width
        screenshot_height = [int]$visibleGuiPng.height
        screenshot_decoded_pixel_sha256 = [string]$visibleGuiPng.decoded_pixel_sha256
        attestation_output_file = [IO.Path]::GetFileName($visibleGuiAttestationInput)
        attestation_output_path_sha256 = [string]$attestationPathBinding.sha256
        signer_key_id = [string]$validatedVisibleGuiTrustRoot.value.key_id
        signer_trust_root_sha256 = $ExpectedVisibleGuiTrustRootSha256.ToLowerInvariant()
        signature_algorithm = 'RSA_PKCS1_SHA256'
        test_fixture = $false
    }
    $visibleGuiSigningRequestEvidence = Write-NewLockedJsonExchange `
        $visibleGuiSigningRequestOutput `
        ($visibleGuiSigningRequestExpected | ConvertTo-Json -Depth 4 -Compress)
    $validatedVisibleGuiSigningRequest = Assert-VisibleGuiSigningRequest `
        $visibleGuiSigningRequestEvidence $visibleGuiScreenshotEvidence `
        $visibleGuiSigningRequestExpected ([DateTimeOffset]::UtcNow)
    Write-Host (("FABRIC_FEDERATION_GUI_SIGNING_REQUEST_READY|request_path={0}|receipt_path={1}|" +
        "screenshot_path={2}|request_sha256={3}|attempt_id={4}|expires_at={5}") -f `
        $visibleGuiSigningRequestOutput, $visibleGuiAttestationInput, $visibleGuiScreenshotInput,
        $visibleGuiSigningRequestEvidence.sha256, $guiAttemptId,
        $guiRequestExpiresAt.ToUniversalTime().ToString('o'))
    $attestationWaitSeconds = [Math]::Max(1, [Math]::Min(
        $HumanTransitionTimeoutSeconds,
        [Math]::Floor(($guiRequestExpiresAt - [DateTimeOffset]::UtcNow).TotalSeconds)))
    Wait-ExternalEvidenceLeaf $visibleGuiAttestationInput $attestationWaitSeconds 'ATTESTATION'
    $visibleGuiAttestationEvidence = Open-LockedEvidence $visibleGuiAttestationInput
    # First cryptographic verification occurs while the prompt is still visible. Use current time
    # only as a provisional upper bound; the same signed receipt is checked again against the exact
    # accept timestamp immediately after the one allowed click.
    $validatedVisibleGuiAttestation = Assert-VisibleGuiAttestation `
        $visibleGuiAttestationEvidence $visibleGuiScreenshotEvidence `
        $visibleGuiSigningRequestEvidence $validatedVisibleGuiSigningRequest `
        $visibleGuiTrustRootEvidence `
        $ExpectedVisibleGuiTrustRootSha256 $guiPromptRenderedAt ([DateTimeOffset]::UtcNow) `
        ([string]$currentBinding.source_commit) $FabricTarget ([string]$currentBinding.fabric_artifact_sha256) `
        $runAttemptId $guiAttemptId $guiChallengeNonce $guiChallengeIssuedAt `
        ([int]$fabricClient.Process.Id) $fabricClientProcessStartedAt `
        $approvedVisibleGuiTrustRootSha256
    Assert-LockedFileIdentity $visibleGuiSigningRequestOutput `
        $visibleGuiSigningRequestEvidence.stream $visibleGuiSigningRequestEvidence.file_identity
    Assert-LockedFileIdentity $visibleGuiScreenshotInput `
        $visibleGuiScreenshotEvidence.stream $visibleGuiScreenshotEvidence.file_identity
    Wait-FileLiteralCount $fabricClient $fabricLog `
        $requiredHumanGuiMarkers[2] 1 $HumanTransitionTimeoutSeconds
    $enablementAcceptedAt = [DateTimeOffset]::UtcNow
    $validatedVisibleGuiAttestation = Assert-VisibleGuiAttestation `
        $visibleGuiAttestationEvidence $visibleGuiScreenshotEvidence `
        $visibleGuiSigningRequestEvidence $validatedVisibleGuiSigningRequest `
        $visibleGuiTrustRootEvidence `
        $ExpectedVisibleGuiTrustRootSha256 $guiPromptRenderedAt $enablementAcceptedAt `
        ([string]$currentBinding.source_commit) $FabricTarget ([string]$currentBinding.fabric_artifact_sha256) `
        $runAttemptId $guiAttemptId $guiChallengeNonce $guiChallengeIssuedAt `
        ([int]$fabricClient.Process.Id) $fabricClientProcessStartedAt `
        $approvedVisibleGuiTrustRootSha256

    # The initial Enable MCAce decision unlocks the authenticated hello.  Only
    # after that result is accepted can Paper produce the verified subject
    # commitment used by every ledger event and federation assertion.
    Wait-FileLiteralCount $fabricClient $fabricLog `
        'MCAce session verified at trust level VERIFIED with risk score 0' 1 `
        ([Math]::Max(60, [int]$HumanTransitionTimeoutSeconds))
    $sourceLocalAuthVerified = $true
    $sourcePaperLog = Join-Path $sourcePaperRoot 'logs\latest.log'
    $uuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-' +
        '[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    $verifiedPaperAdmissionPattern = 'Accepted signed MCAce admission state for ' +
        "(?<subject>$uuidPattern): admission=VERIFIED, trust=VERIFIED, risk=0"
    $sourcePaperAdmission = Wait-FileRegexMatch `
        $sourcePaperService $sourcePaperLog $verifiedPaperAdmissionPattern 30
    $sourceSubjectId = [string]$sourcePaperAdmission.Groups['subject'].Value
    $sourceSubjectCommitmentSha256 = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes(
        "MCACE_SUBJECT_COMMITMENT_V1`nsubject=$sourceSubjectId`nchallenge=$guiChallengeNonce`n"))
    $sourcePaperAdmissionVerified = $true

    # Preserve the real prompt/sign/accept chronology in the append-only ledger,
    # even though the subject commitment becomes available only after auth.
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'GUI_PROMPT_RENDERED' '' 'FABRIC_CLIENT' `
        $fabricClient.Process 'mcace-source' $sourceConnectionId $federationSessionId `
        $sourceSubjectCommitmentSha256 $requiredHumanGuiMarkers[1] `
        $guiPromptRenderedAt.ToUniversalTime().ToString('o')
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'GUI_SIGNED_RECEIPT_VERIFIED' '' 'SUPERVISOR' `
        (Get-Process -Id $PID) 'mcace-source' $sourceConnectionId $federationSessionId `
        $sourceSubjectCommitmentSha256 ([string]$visibleGuiAttestationEvidence.sha256) `
        $validatedVisibleGuiAttestation.value.signed_at
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'GUI_ACCEPTED' '' 'FABRIC_CLIENT' `
        $fabricClient.Process 'mcace-source' $sourceConnectionId $federationSessionId `
        $sourceSubjectCommitmentSha256 $requiredHumanGuiMarkers[2] `
        $enablementAcceptedAt.ToUniversalTime().ToString('o')
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'SOURCE_CONNECTION_VERIFIED' '' 'FABRIC_CLIENT' `
        $fabricClient.Process 'mcace-source' $sourceConnectionId $federationSessionId `
        $sourceSubjectCommitmentSha256 'source signed session and paper admission verified'

    $playerName = Get-FabricDevelopmentPlayerName $fabricLog
    $issuePattern = 'MCAce: federation issue status=CONSENT_ISSUED'
    $issueBaseline = Get-ServiceRegexCount $sourceService $issuePattern
    $consentIssuedAt = [DateTimeOffset]::UtcNow
    $earliestAssertionExpiry = $consentIssuedAt.AddSeconds($FederationAssertionTtlSeconds)
    $targetEvidenceDeadline = $earliestAssertionExpiry.AddSeconds(-15)
    $preExpiryProbeAt = $earliestAssertionExpiry.AddSeconds(-8)
    Send-ServiceCommand $sourceService "mcacefederation issue $playerName mcace-target"
    Wait-NewServiceRegex $sourceService $issuePattern $issueBaseline 30
    $consentIssueObservedAt = [DateTimeOffset]::UtcNow
    $latestAssertionExpiry = $consentIssueObservedAt.AddSeconds($FederationAssertionTtlSeconds)
    Wait-FileLiteralCount $fabricClient $fabricLog $requiredHumanGuiMarkers[3] 1 30
    $grantReadyPattern = 'MCAce federation consent response status=GRANT_READY player=' +
        [regex]::Escape($sourceSubjectId)
    $null = Wait-FileRegexMatch $sourceService $sourceService.StdoutPath $grantReadyPattern 30
    $sourceGrantReadyObserved = $true
    Wait-FileLiteralCount $fabricClient $fabricLog `
        'MCAce stored a one-time federation grant in memory only' 1 30

    # Runtime negative 1: the proxy really sends a second source assertion. The Fabric
    # client must reject it at its connection-scoped one-shot gate, and the source proxy
    # must receive no second GRANT_READY response.
    $sourceRejectionMarker = 'MCAce rejected federation source export because its one-shot human approval is absent, consumed, or inherited'
    $sourceRejectionBaseline = Get-FileLiteralCount $fabricLog $sourceRejectionMarker
    $sourceGrantReadyBaseline = Get-ServiceRegexCount $sourceService $grantReadyPattern
    $sourceSecondIssueBaseline = Get-ServiceRegexCount $sourceService $issuePattern
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'SOURCE_SECOND_EXPORT_REQUESTED' `
        $sourceSecondOperationAttemptId 'SOURCE_PROXY' $sourceService.Process 'mcace-target' `
        $sourceConnectionId $federationSessionId $sourceSubjectCommitmentSha256 `
        "mcacefederation issue subject-commitment mcace-target"
    Send-ServiceCommand $sourceService "mcacefederation issue $playerName mcace-target"
    Wait-NewServiceRegex $sourceService $issuePattern $sourceSecondIssueBaseline 30
    $sourceSecondAssertionRuntimeRequested = $true
    Wait-FileLiteralCount $fabricClient $fabricLog $sourceRejectionMarker `
        ($sourceRejectionBaseline + 1) 30
    $sourceSecondAssertionFabricRejectionCountDelta =
        (Get-FileLiteralCount $fabricLog $sourceRejectionMarker) - $sourceRejectionBaseline
    if ($sourceSecondAssertionFabricRejectionCountDelta -ne 1) {
        throw 'FABRIC_FEDERATION_GUI_SOURCE_SECOND_ASSERTION_REJECTION_COUNT_INVALID'
    }
    $sourceSecondAssertionFabricRejected = $true
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'SOURCE_SECOND_EXPORT_REJECTED' `
        $sourceSecondOperationAttemptId 'FABRIC_CLIENT' $fabricClient.Process 'mcace-target' `
        $sourceConnectionId $federationSessionId $sourceSubjectCommitmentSha256 $sourceRejectionMarker
    Start-Sleep -Seconds 2
    $sourceSecondAssertionGrantReadyDelta =
        (Get-FileRegexCount $sourceService.StdoutPath $grantReadyPattern) - $sourceGrantReadyBaseline
    if ($sourceSecondAssertionGrantReadyDelta -ne 0) {
        throw 'FABRIC_FEDERATION_GUI_SOURCE_SECOND_ASSERTION_UNEXPECTED_GRANT_READY'
    }
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'SOURCE_SECOND_EXPORT_NO_GRANT_CONFIRMED' `
        $sourceSecondOperationAttemptId 'SOURCE_PROXY' $sourceService.Process 'mcace-target' `
        $sourceConnectionId $federationSessionId $sourceSubjectCommitmentSha256 `
        'source grant-ready delta exactly zero'

    Write-Host ''
    Write-Host "TARGET HUMAN PHASE: disconnect from source and use Minecraft Direct Connection to join $targetAddress. The accepted connection enablement is inherited; no second prompt is expected."
    Write-Host "Complete this phase with at least 15 seconds remaining in the conservative $FederationAssertionTtlSeconds-second assertion window."
    $transitionTimeout = Get-SecondsUntilDeadline `
        $targetEvidenceDeadline $HumanTransitionTimeoutSeconds `
        'FABRIC_FEDERATION_GUI_TARGET_TRANSITION_WINDOW_EXPIRED'
    Wait-FileLiteralCount $sourcePaperService $sourcePaperLog `
        "$playerName left the game" 1 $transitionTimeout
    $sourceDisconnectedBeforeTargetAuth = $true
    $targetAuthTimeout = Get-SecondsUntilDeadline `
        $targetEvidenceDeadline $HumanTransitionTimeoutSeconds `
        'FABRIC_FEDERATION_GUI_TARGET_AUTH_WINDOW_EXPIRED'
    Wait-FileLiteralCount $fabricClient $fabricLog `
        'MCAce session verified at trust level VERIFIED with risk score 0' 2 $targetAuthTimeout
    $targetLocalAuthVerified = $true
    Wait-FileLiteralCount $fabricClient $fabricLog $requiredHumanGuiMarkers[5] 1 `
        (Get-SecondsUntilDeadline $targetEvidenceDeadline $HumanTransitionTimeoutSeconds `
            'FABRIC_FEDERATION_GUI_TARGET_ENABLEMENT_INHERITANCE_WINDOW_EXPIRED')
    $targetPaperLog = Join-Path $targetPaperRoot 'logs\latest.log'
    $targetAdmissionTimeout = Get-SecondsUntilDeadline `
        $targetEvidenceDeadline 30 'FABRIC_FEDERATION_GUI_TARGET_ADMISSION_WINDOW_EXPIRED'
    $targetPaperAdmission = Wait-FileRegexMatch `
        $targetPaperService $targetPaperLog $verifiedPaperAdmissionPattern $targetAdmissionTimeout
    $targetSubjectId = [string]$targetPaperAdmission.Groups['subject'].Value
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($sourceSubjectId, $targetSubjectId)) {
        throw 'FABRIC_FEDERATION_GUI_SOURCE_TARGET_SUBJECT_MISMATCH'
    }
    $targetSubjectBound = $true
    $targetSubjectCommitmentSha256 = Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes(
        "MCACE_SUBJECT_COMMITMENT_V1`nsubject=$targetSubjectId`nchallenge=$guiChallengeNonce`n"))
    if ($targetSubjectCommitmentSha256 -cne $sourceSubjectCommitmentSha256) {
        throw 'FABRIC_FEDERATION_GUI_SOURCE_TARGET_SUBJECT_COMMITMENT_MISMATCH'
    }
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'TARGET_CONNECTION_VERIFIED' '' 'FABRIC_CLIENT' `
        $fabricClient.Process 'mcace-target' $targetConnectionId $federationSessionId `
        $targetSubjectCommitmentSha256 'target signed session and paper admission verified'
    $targetPaperAdmissionVerified = $true
    $targetDisconnectMarker = "$playerName left the game"
    $targetDisconnectBaseline = Get-FileLiteralCount $targetPaperLog $targetDisconnectMarker
    Assert-NewPaperVerifiedSnapshot $targetPaperService $targetPaperService.StdoutPath $playerName `
        (Get-SecondsUntilDeadline $targetEvidenceDeadline 10 `
            'FABRIC_FEDERATION_GUI_TARGET_LOCAL_STATE_WINDOW_EXPIRED')
    Wait-FileLiteralCount $fabricClient $fabricLog $requiredHumanGuiMarkers[4] 1 `
        (Get-SecondsUntilDeadline $targetEvidenceDeadline $HumanTransitionTimeoutSeconds `
            'FABRIC_FEDERATION_GUI_TARGET_ENABLEMENT_INHERITANCE_WINDOW_EXPIRED')
    Wait-FileLiteralCount $fabricClient $fabricLog $requiredHumanGuiMarkers[6] 1 `
        (Get-SecondsUntilDeadline $targetEvidenceDeadline $HumanTransitionTimeoutSeconds `
            'FABRIC_FEDERATION_GUI_TARGET_AUTHORIZATION_PROMOTION_WINDOW_EXPIRED')
    $targetObservationPattern = 'MCAce federation presentation status=OBSERVED player=' +
        [regex]::Escape($targetSubjectId) + ' \(observation-only\)'
    $null = Wait-FileRegexMatch $targetService $targetService.StdoutPath $targetObservationPattern `
        (Get-SecondsUntilDeadline $targetEvidenceDeadline 30 `
            'FABRIC_FEDERATION_GUI_TARGET_OBSERVATION_WINDOW_EXPIRED')
    $targetObservationRecorded = $true
    $presentationSent = $true
    $targetOnePattern = 'MCAce: federation enabled=true configured=true audit=HEALTHY ' +
        'audit_backlog=0 audit_committed=[0-9]+ audit_failures=0 local=mcace-target peers=1 pending=0 observations=1'
    $targetOneBaseline = Get-ServiceRegexCount $targetService $targetOnePattern
    Send-ServiceCommand $targetService 'mcacefederation status'
    Wait-NewServiceRegex $targetService $targetOnePattern $targetOneBaseline `
        (Get-SecondsUntilDeadline $targetEvidenceDeadline 10 `
            'FABRIC_FEDERATION_GUI_TARGET_INITIAL_OBSERVATION_WINDOW_EXPIRED')
    $targetObservationCountOne = $true
    Assert-NewPaperVerifiedSnapshot $targetPaperService $targetPaperService.StdoutPath $playerName `
        (Get-SecondsUntilDeadline $targetEvidenceDeadline 10 `
            'FABRIC_FEDERATION_GUI_TARGET_POST_OBSERVATION_STATE_WINDOW_EXPIRED')
    Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
        $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline
    Assert-ExactHumanGuiMarkers $fabricLog

    # FederationDocuments creates issuedAt/expiresAt while the issue command runs. The pre-send and
    # post-CONSENT_ISSUED timestamps therefore bound the real expiry. Repeated one-count probes near
    # the lower bound plus accepting zero only after the upper bound reject premature cleanup.
    while ([DateTimeOffset]::UtcNow -lt $preExpiryProbeAt) {
        Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
            $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline
        Start-Sleep -Seconds 1
    }
    Assert-NewPaperVerifiedSnapshot $targetPaperService $targetPaperService.StdoutPath $playerName `
        (Get-SecondsUntilDeadline $earliestAssertionExpiry 3 `
            'FABRIC_FEDERATION_GUI_PRE_EXPIRY_LOCAL_STATE_PROOF_LATE')
    $preExpiryStatusCutoff = $earliestAssertionExpiry.AddSeconds(-2)
    while ([DateTimeOffset]::UtcNow -lt $preExpiryStatusCutoff) {
        Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
            $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline
        $preExpiryOneBaseline = Get-ServiceRegexCount $targetService $targetOnePattern
        Send-ServiceCommand $targetService 'mcacefederation status'
        Wait-NewServiceRegex $targetService $targetOnePattern $preExpiryOneBaseline `
            (Get-SecondsUntilDeadline $earliestAssertionExpiry 2 `
                'FABRIC_FEDERATION_GUI_PRE_EXPIRY_OBSERVATION_PROOF_LATE')
        if ([DateTimeOffset]::UtcNow -ge $earliestAssertionExpiry) {
            throw 'FABRIC_FEDERATION_GUI_PRE_EXPIRY_OBSERVATION_PROOF_LATE'
        }
        $targetObservationOneBeforeExpiry = $true
        Start-Sleep -Seconds 1
    }
    if (-not $targetObservationOneBeforeExpiry) {
        throw 'FABRIC_FEDERATION_GUI_PRE_EXPIRY_OBSERVATION_PROOF_MISSING'
    }
    Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
        $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline

    # The initial readiness observations=0 line is excluded by a baseline count. A new zero is
    # accepted only after the lower-bound expiry and while the exact target session remains live.
    $targetZeroPattern = 'MCAce: federation enabled=true configured=true audit=HEALTHY ' +
        'audit_backlog=0 audit_committed=[0-9]+ audit_failures=0 local=mcace-target peers=1 pending=0 observations=0'
    $targetZeroBaseline = Get-FileRegexCount $targetService.StdoutPath $targetZeroPattern
    $notBefore = $latestAssertionExpiry.AddSeconds(2)
    while ([DateTimeOffset]::UtcNow -lt $notBefore) {
        Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
            $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline
        Start-Sleep -Seconds 1
    }
    $expiryDeadline = $latestAssertionExpiry.AddSeconds(30)
    while ([DateTimeOffset]::UtcNow -lt $expiryDeadline -and
            (Get-FileRegexCount $targetService.StdoutPath $targetZeroPattern) -le $targetZeroBaseline) {
        Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
            $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline
        Send-ServiceCommand $targetService 'mcacefederation status'
        Start-Sleep -Seconds 2
    }
    if ((Get-FileRegexCount $targetService.StdoutPath $targetZeroPattern) -le $targetZeroBaseline) {
        throw 'FABRIC_FEDERATION_GUI_TARGET_OBSERVATION_DID_NOT_EXPIRE'
    }
    $observationExpired = $true
    $targetObservationZero = $true
    Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
        $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline
    Assert-NewPaperVerifiedSnapshot $targetPaperService $targetPaperService.StdoutPath $playerName 10
    Assert-TargetSessionStillConnected $fabricClient $targetService $targetPaperService `
        $targetPaperLog $targetDisconnectMarker $targetDisconnectBaseline
    $localStateUnchanged = $targetPaperAdmissionVerified
    $targetSessionConnectedThroughExpiry = $true

    # Runtime negative 2: after promotion, the inherited target connection attempts a
    # real export to its pinned peer. Its inherited authorization must reject the request
    # and the target proxy must receive no GRANT_READY response.
    $targetGrantReadyPattern = 'MCAce federation consent response status=GRANT_READY player=' +
        [regex]::Escape($targetSubjectId)
    $targetRejectionBaseline = Get-FileLiteralCount $fabricLog $sourceRejectionMarker
    $targetGrantReadyBaseline = Get-ServiceRegexCount $targetService $targetGrantReadyPattern
    $targetIssueBaseline = Get-ServiceRegexCount $targetService $issuePattern
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'TARGET_INHERITED_EXPORT_REQUESTED' `
        $targetInheritedOperationAttemptId 'TARGET_PROXY' $targetService.Process 'mcace-source' `
        $targetConnectionId $federationSessionId $targetSubjectCommitmentSha256 `
        'mcacefederation issue subject-commitment mcace-source'
    Send-ServiceCommand $targetService "mcacefederation issue $playerName mcace-source"
    Wait-NewServiceRegex $targetService $issuePattern $targetIssueBaseline 30
    $targetInheritedExportRuntimeRequested = $true
    Wait-FileLiteralCount $fabricClient $fabricLog $sourceRejectionMarker `
        ($targetRejectionBaseline + 1) 30
    $targetInheritedExportFabricRejectionCountDelta =
        (Get-FileLiteralCount $fabricLog $sourceRejectionMarker) - $targetRejectionBaseline
    if ($targetInheritedExportFabricRejectionCountDelta -ne 1) {
        throw 'FABRIC_FEDERATION_GUI_TARGET_INHERITED_EXPORT_REJECTION_COUNT_INVALID'
    }
    $targetInheritedExportFabricRejected = $true
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'TARGET_INHERITED_EXPORT_REJECTED' `
        $targetInheritedOperationAttemptId 'FABRIC_CLIENT' $fabricClient.Process 'mcace-source' `
        $targetConnectionId $federationSessionId $targetSubjectCommitmentSha256 $sourceRejectionMarker
    Start-Sleep -Seconds 2
    $targetInheritedExportGrantReadyDelta =
        (Get-FileRegexCount $targetService.StdoutPath $targetGrantReadyPattern) - $targetGrantReadyBaseline
    if ($targetInheritedExportGrantReadyDelta -ne 0) {
        throw 'FABRIC_FEDERATION_GUI_TARGET_INHERITED_EXPORT_UNEXPECTED_GRANT_READY'
    }
    $null = Add-ServiceRuntimeEvent $runtimeLedger 'TARGET_INHERITED_EXPORT_NO_GRANT_CONFIRMED' `
        $targetInheritedOperationAttemptId 'TARGET_PROXY' $targetService.Process 'mcace-source' `
        $targetConnectionId $federationSessionId $targetSubjectCommitmentSha256 `
        'target grant-ready delta exactly zero'

    $runtimeLedgerSeal = Complete-RuntimeLedger $runtimeLedger $guiChallengeNonce

    Stop-JavaService $fabricClient ''
    $fabricClient = $null
    $clientShutdownCompleted = $true
    $runtimeAssertionsComplete = $true
} catch {
    $failure = $_
} finally {
    foreach ($cleanup in @(
            @('fabric', $fabricClient, ''),
            @('target-paper', $targetPaperService, 'stop'),
            @('source-paper', $sourcePaperService, 'stop'),
            @('target-proxy', $targetService, 'end'),
            @('source-proxy', $sourceService, 'end'))) {
        try {
            if ($cleanup[0] -ceq 'fabric') {
                Stop-JavaService $cleanup[1] $cleanup[2]
            } else {
                Stop-FederationJavaService $cleanup[1] $cleanup[2]
            }
        } catch {
            if ($null -eq $failure) { $failure = $_ }
        }
    }
    try { Stop-RunTokenJavaProcesses $runToken }
    catch { if ($null -eq $failure) { $failure = $_ } }
}

$remainingOwnedProcessCount = -1
$cleanupPortsFree = $false
try {
    $remainingOwnedProcessCount = @(Get-RunTokenJavaProcesses $runToken).Count
    $cleanupPortsFree = @($allPorts | Where-Object { -not (Test-LoopbackPortFree $_) }).Count -eq 0
    if ($remainingOwnedProcessCount -ne 0 -or -not $cleanupPortsFree) {
        throw 'FABRIC_FEDERATION_GUI_ZERO_PROCESS_AND_PORT_RESIDUE_REQUIRED'
    }
    if ($null -eq $runLocalBefore) {
        throw 'FABRIC_FEDERATION_GUI_RUN_LOCAL_PRESTART_BINDING_REQUIRED'
    }
    $runLocalAfter = Get-RunLocalRuntimeBinding `
        $sourceRuntime $targetRuntime $sourcePaperRuntime $targetPaperRuntime
    Assert-RunLocalRuntimeBinding $runLocalAfter $currentBinding
    Assert-BindingUnchanged $runLocalBefore $runLocalAfter `
        'FABRIC_FEDERATION_GUI_RUN_LOCAL_INPUT_CHANGED'
    $postRunInput = Get-ImmutableInputBinding
    Assert-BindingUnchanged $preBuildInput $postRunInput `
        'FABRIC_FEDERATION_GUI_IMMUTABLE_INPUT_CHANGED_DURING_RUN'
    $currentAfterRun = Get-CurrentBinding
    Assert-BindingUnchanged $currentBinding $currentAfterRun `
        'FABRIC_FEDERATION_GUI_CURRENT_BINDING_CHANGED_DURING_RUN'
    $ledgerDoc = Open-LockedFileBytes (Join-Path $runRoot 'runtime-events.jsonl') 256 1048576 'RUNTIME_LEDGER'
    try {
        $runtimeLedgerEvidenceBytes = [byte[]]$ledgerDoc.bytes
        $validatedRuntimeLedger = Assert-RuntimeLedgerBytes $runtimeLedgerEvidenceBytes `
            ([string]$currentBinding.source_commit) $FabricTarget $runAttemptId $guiChallengeNonce
    } finally { $ledgerDoc.stream.Dispose() }
} catch {
    if ($null -eq $failure) { $failure = $_ }
}

if ($null -ne $failure -or -not $runtimeAssertionsComplete -or -not $clientShutdownCompleted) {
    $message = if ($null -ne $failure) { $failure.Exception.Message } else {
        'real Fabric federation GUI assertions did not reach the commit boundary'
    }
    if ($null -ne $visibleGuiScreenshotEvidence) { $visibleGuiScreenshotEvidence.stream.Dispose() }
    if ($null -ne $visibleGuiAttestationEvidence) { $visibleGuiAttestationEvidence.stream.Dispose() }
    if ($null -ne $visibleGuiSigningRequestEvidence) { $visibleGuiSigningRequestEvidence.stream.Dispose() }
    $postRunTrustRootEvidence.stream.Dispose()
    $visibleGuiTrustRootEvidence.stream.Dispose()
    if ($runRootCreated) { Remove-OwnedRunDirectory $runRoot }
    throw "FABRIC_FEDERATION_GUI_HANDOFF_FAILED: $message"
}

$report = [ordered]@{
    schema = $reportSchema
    generated_at = [DateTimeOffset]::UtcNow.ToString('o')
    source_mode = 'EXECUTED_REAL_FABRIC_GUI'
    status = 'passed'
    artifact_class = $artifactClass
    source_commit = [string]$currentBinding.source_commit
    run_attempt_id = $runAttemptId
    gui_attempt_id = $guiAttemptId
    gui_challenge_nonce = $guiChallengeNonce
    gui_challenge_issued_at = $guiChallengeIssuedAt.ToUniversalTime().ToString('o')
    gui_signing_request_created_at = [string]$validatedVisibleGuiSigningRequest.value.request_created_at
    gui_signing_request_expires_at = $guiRequestExpiresAt.ToUniversalTime().ToString('o')
    fabric_client_started_at = $fabricClientStartedAt.ToUniversalTime().ToString('o')
    gui_prompt_rendered_at = $guiPromptRenderedAt.ToUniversalTime().ToString('o')
    enablement_consent_accepted_at = $enablementAcceptedAt.ToUniversalTime().ToString('o')
    fabric_target = $FabricTarget
    minecraft_version = [string]$fabricDescriptor.minecraft_version
    fabric_api_version = [string]$fabricDescriptor.fabric_api_version
    fabric_artifact_kind = [string]$fabricDescriptor.artifact_kind
    fabric_java_major = [int]$fabricDescriptor.java_major
    fabric_runtime_mode = $fabricRuntimeMode
    fabric_build_id = [string]$currentBinding.fabric_build_id
    fabric_codesource_sha256_observed = [string]$currentBinding.fabric_artifact_sha256
    source_proxy = $SourceProxy
    target_proxy = $TargetProxy
    federation_assertion_ttl_seconds = $FederationAssertionTtlSeconds
    operator_visible_gui_attestation_count = 1
    human_visible_federation_consent_count = 1
    operator_visible_gui_attestation_schema = $visibleGuiAttestationSchema
    operator_visible_gui_attestation_source_mode = $visibleGuiAttestationSourceMode
    operator_visible_gui_tool = 'computer-use'
    operator_visible_gui_session_id = [string]$validatedVisibleGuiAttestation.value.session_id
    operator_visible_gui_window_id = [string]$validatedVisibleGuiAttestation.value.window_id
    operator_visible_gui_client_process_id = [int]$validatedVisibleGuiAttestation.value.client_process_id
    operator_visible_gui_client_process_started_at = [string]$validatedVisibleGuiAttestation.value.client_process_started_at
    operator_visible_gui_attempt_id = [string]$validatedVisibleGuiAttestation.value.attempt_id
    operator_visible_gui_gui_attempt_id = [string]$validatedVisibleGuiAttestation.value.gui_attempt_id
    operator_visible_gui_signing_request_schema = $visibleGuiSigningRequestSchema
    operator_visible_gui_signing_request_domain = $visibleGuiSigningRequestDomain
    operator_visible_gui_signing_request_sha256 = [string]$visibleGuiSigningRequestEvidence.sha256
    operator_visible_gui_signing_request_size_bytes = [long]$visibleGuiSigningRequestEvidence.size_bytes
    operator_visible_gui_signing_request_path_sha256 = [string]$validatedVisibleGuiSigningRequest.value.signing_request_path_sha256
    operator_visible_gui_screenshot_path_sha256 = [string]$validatedVisibleGuiSigningRequest.value.screenshot_path_sha256
    operator_visible_gui_attestation_output_path_sha256 = [string]$validatedVisibleGuiSigningRequest.value.attestation_output_path_sha256
    operator_visible_gui_captured_at = [string]$validatedVisibleGuiAttestation.captured_at
    operator_visible_gui_signed_at = [string]$validatedVisibleGuiAttestation.signed_at
    operator_visible_gui_source_commit = [string]$validatedVisibleGuiAttestation.value.source_commit
    operator_visible_gui_signer_key_id = [string]$validatedVisibleGuiAttestation.value.signer_key_id
    operator_visible_gui_trust_root_sha256 = $ExpectedVisibleGuiTrustRootSha256.ToLowerInvariant()
    operator_visible_gui_signature_algorithm = 'RSA_PKCS1_SHA256'
    operator_visible_gui_attestation_json_sha256 = [string]$visibleGuiAttestationEvidence.sha256
    operator_visible_gui_attestation_json_size_bytes = [long]$visibleGuiAttestationEvidence.size_bytes
    operator_visible_gui_screenshot_sha256 = [string]$visibleGuiScreenshotEvidence.sha256
    operator_visible_gui_screenshot_size_bytes = [long]$visibleGuiScreenshotEvidence.size_bytes
    operator_visible_gui_screenshot_width = [int]$validatedVisibleGuiAttestation.screenshot_width
    operator_visible_gui_screenshot_height = [int]$validatedVisibleGuiAttestation.screenshot_height
    operator_visible_gui_screenshot_decoded_pixel_sha256 = [string]$validatedVisibleGuiAttestation.screenshot_decoded_pixel_sha256
    release_bundle_manifest_sha256 = [string]$releaseBundleBinding.manifest_sha256
    release_bundle_fabric_jar_file = [string]$releaseBundleBinding.fabric_jar_file
    release_bundle_fabric_jar_sha256 = [string]$releaseBundleBinding.fabric_jar_sha256
    release_bundle_fabric_jar_size_bytes = [long]$releaseBundleBinding.fabric_jar_size_bytes
    runtime_ledger_sha256 = Get-BytesSha256 $runtimeLedgerEvidenceBytes
    runtime_ledger_size_bytes = [long]$runtimeLedgerEvidenceBytes.Length
    runtime_ledger_event_count = [int]$validatedRuntimeLedger.event_count
    runtime_ledger_head_sha256 = [string]$validatedRuntimeLedger.head_sha256
    runtime_ledger_supervisor_seal_sha256 = [string]$validatedRuntimeLedger.supervisor_seal_sha256
    source_negative_attempt_id = [string]$validatedRuntimeLedger.source_negative_attempt_id
    source_negative_peer = [string]$validatedRuntimeLedger.source_negative_peer
    source_negative_connection_id = [string]$validatedRuntimeLedger.source_negative_connection_id
    source_negative_session_id = [string]$validatedRuntimeLedger.source_negative_session_id
    source_negative_subject_commitment_sha256 = [string]$validatedRuntimeLedger.source_negative_subject_commitment_sha256
    target_negative_attempt_id = [string]$validatedRuntimeLedger.target_negative_attempt_id
    target_negative_peer = [string]$validatedRuntimeLedger.target_negative_peer
    target_negative_connection_id = [string]$validatedRuntimeLedger.target_negative_connection_id
    target_negative_session_id = [string]$validatedRuntimeLedger.target_negative_session_id
    target_negative_subject_commitment_sha256 = [string]$validatedRuntimeLedger.target_negative_subject_commitment_sha256
    operator_attested_visible_computer_use_session = $true
    operator_attested_no_headless_or_synthetic_input = $true
    external_visible_gui_attestation_validated = $true
    raw_peer_evidence_used = $false
    raw_content_retained = $false
    fabric_artifact_mode_verified = $true
    source_local_auth_verified = $sourceLocalAuthVerified
    source_paper_admission_verified = $sourcePaperAdmissionVerified
    enablement_consent_requested = $true
    enablement_consent_rendered = $true
    enablement_consent_accepted = $true
    source_export_permit_reserved = $true
    source_grant_stored_memory_only = $true
    source_grant_ready_observed = $sourceGrantReadyObserved
    source_disconnected_before_target_auth = $sourceDisconnectedBeforeTargetAuth
    target_local_auth_verified = $targetLocalAuthVerified
    target_import_consent_inherited = $true
    presentation_sent = $presentationSent
    target_authorization_promoted_after_presentation = $true
    source_second_assertion_runtime_requested = $sourceSecondAssertionRuntimeRequested
    source_second_assertion_fabric_one_shot_rejection_observed = $sourceSecondAssertionFabricRejected
    source_second_assertion_fabric_rejection_count_delta = [int]$sourceSecondAssertionFabricRejectionCountDelta
    source_second_assertion_grant_ready_delta = [int]$sourceSecondAssertionGrantReadyDelta
    target_inherited_export_runtime_requested = $targetInheritedExportRuntimeRequested
    target_inherited_export_fabric_rejection_observed = $targetInheritedExportFabricRejected
    target_inherited_export_fabric_rejection_count_delta = [int]$targetInheritedExportFabricRejectionCountDelta
    target_inherited_export_grant_ready_delta = [int]$targetInheritedExportGrantReadyDelta
    target_observation_recorded = $targetObservationRecorded
    target_subject_bound = $targetSubjectBound
    target_observation_status_count_one = $targetObservationCountOne
    target_observation_status_one_before_expiry = $targetObservationOneBeforeExpiry
    target_paper_admission_verified = $targetPaperAdmissionVerified
    local_trust_risk_admission_unchanged = $localStateUnchanged
    target_session_connected_through_expiry = $targetSessionConnectedThroughExpiry
    observation_expired = $observationExpired
    target_observation_status_zero_after_expiry = $targetObservationZero
    client_shutdown_completed = $clientShutdownCompleted
    cleanup_ports_free = $cleanupPortsFree
    remaining_owned_process_count = $remainingOwnedProcessCount
    passed = $true
}
try {
    # Delete every mutable runtime artifact before the first passing report byte is created. Report
    # and binding are immutable before the external post-run supervisor signs their raw hashes;
    # commit.json is created only after that detached receipt verifies.
    Clear-OwnedRunForEvidence $runRoot
    $null = Write-NewBytesFile (Join-Path $runRoot 'visible-gui-attestation.json') `
        ([byte[]]$visibleGuiAttestationEvidence.bytes)
    $null = Write-NewBytesFile (Join-Path $runRoot 'visible-gui-signing-request.json') `
        ([byte[]]$visibleGuiSigningRequestEvidence.bytes)
    $null = Write-NewBytesFile (Join-Path $runRoot 'visible-gui.png') `
        ([byte[]]$visibleGuiScreenshotEvidence.bytes)
    $null = Write-NewBytesFile (Join-Path $runRoot 'runtime-events.jsonl') `
        ([byte[]]$runtimeLedgerEvidenceBytes)
    $immutableDocuments = Write-ImmutableReportAndBinding $runRoot $report $currentBinding
    $reportRaw = [Text.UTF8Encoding]::new($false, $true).GetString(
        [byte[]]$immutableDocuments.report_bytes)
    $bindingRaw = [Text.UTF8Encoding]::new($false, $true).GetString(
        [byte[]]$immutableDocuments.binding_bytes)
    $null = Assert-PassingReportRaw $reportRaw $currentBinding $SourceProxy $TargetProxy
    $null = Assert-BindingRaw $bindingRaw ([string]$immutableDocuments.report_sha256) `
        $report $currentBinding

    $postRunOperationAttemptId = New-CryptographicHex 16
    $postRunChallengeNonce = New-CryptographicHex 32
    $postRunChallengeIssuedAt = [DateTimeOffset]::UtcNow
    $reportEvidenceForSigning = [pscustomobject]@{
        sha256 = [string]$immutableDocuments.report_sha256
        size_bytes = [long]$immutableDocuments.report_size_bytes
    }
    $bindingEvidenceForSigning = [pscustomobject]@{
        sha256 = [string]$immutableDocuments.binding_sha256
        size_bytes = [long]$immutableDocuments.binding_size_bytes
    }
    $ledgerEvidenceForSigning = [pscustomobject]@{
        sha256 = Get-BytesSha256 $runtimeLedgerEvidenceBytes
        size_bytes = [long]$runtimeLedgerEvidenceBytes.Length
    }
    $postRunExpected = Get-PostRunReceiptExpectedBinding `
        $releaseBundleBinding $report $reportEvidenceForSigning $bindingEvidenceForSigning `
        $visibleGuiAttestationEvidence $visibleGuiScreenshotEvidence `
        $validatedVisibleGuiAttestation $ledgerEvidenceForSigning $validatedRuntimeLedger `
        $postRunOperationAttemptId $postRunChallengeNonce `
        $postRunChallengeIssuedAt.ToUniversalTime().ToString('o')
    $postRunSigningRequest = [ordered]@{}
    foreach ($name in $postRunReceiptPropertyNames) {
        if ($postRunExpected.Contains($name)) {
            $postRunSigningRequest[$name] = $postRunExpected[$name]
        } else {
            switch ($name) {
                'schema' { $postRunSigningRequest[$name] = $postRunReceiptSchema }
                'artifact_class' { $postRunSigningRequest[$name] = $postRunReceiptArtifactClass }
                'source_mode' { $postRunSigningRequest[$name] = 'EXTERNAL_POSTRUN_SUPERVISOR' }
                'signed_at' { $postRunSigningRequest[$name] = '' }
                'signer_key_id' {
                    $postRunSigningRequest[$name] = [string]$validatedPostRunTrustRoot.value.key_id
                }
                'signer_trust_root_sha256' {
                    $postRunSigningRequest[$name] = $ExpectedPostRunSupervisorTrustRootSha256.ToLowerInvariant()
                }
                'signature_algorithm' { $postRunSigningRequest[$name] = 'RSA_PKCS1_SHA256' }
                'test_fixture' { $postRunSigningRequest[$name] = $false }
                'signature_base64' { $postRunSigningRequest[$name] = '' }
                default { throw "FABRIC_FEDERATION_GUI_POSTRUN_SIGNING_REQUEST_FIELD_UNBOUND: $name" }
            }
        }
    }
    $postRunRequestBytes = Write-NewUtf8File $postRunSigningRequestOutput `
        ($postRunSigningRequest | ConvertTo-Json -Depth 5 -Compress)
    Write-Host (("FABRIC_FEDERATION_GUI_POSTRUN_SIGNING_REQUEST_READY|path={0}|sha256={1}|" +
        "operation_attempt_id={2}|challenge_nonce={3}") -f $postRunSigningRequestOutput,
        (Get-BytesSha256 $postRunRequestBytes), $postRunOperationAttemptId, $postRunChallengeNonce)
    Write-Host 'The external post-run supervisor must set signed_at, sign Get-PostRunReceiptSigningPayload with its out-of-band private key, and atomically create the requested receipt.'
    Wait-ExternalEvidenceLeaf $postRunReceiptInput $PostRunReceiptTimeoutSeconds 'POSTRUN_RECEIPT'
    $postRunReceiptEvidence = Open-LockedEvidence $postRunReceiptInput
    $validatedPostRunReceipt = Assert-PostRunReceipt $postRunReceiptEvidence `
        $postRunTrustRootEvidence $ExpectedPostRunSupervisorTrustRootSha256 `
        $approvedPostRunTrustRootSha256 $postRunExpected $postRunChallengeIssuedAt
    $null = Write-NewBytesFile (Join-Path $runRoot 'post-run-receipt.json') `
        ([byte[]]$postRunReceiptEvidence.bytes)
    $null = Write-FederationCommit $runRoot $report $immutableDocuments `
        $postRunReceiptEvidence $validatedPostRunReceipt.value
    $reportPath = [string]$immutableDocuments.report_path
    $null = Assert-EvidenceSet $reportPath $currentBinding $SourceProxy $TargetProxy `
        $visibleGuiTrustRootEvidence $postRunTrustRootEvidence $releaseBundleBinding `
        $approvedVisibleGuiTrustRootSha256 $approvedPostRunTrustRootSha256
} catch {
    if ($runRootCreated) { Remove-OwnedRunDirectory $runRoot }
    throw
} finally {
    if ($null -ne $postRunReceiptEvidence) { $postRunReceiptEvidence.stream.Dispose() }
    if ($null -ne $visibleGuiScreenshotEvidence) { $visibleGuiScreenshotEvidence.stream.Dispose() }
    if ($null -ne $visibleGuiAttestationEvidence) { $visibleGuiAttestationEvidence.stream.Dispose() }
    if ($null -ne $visibleGuiSigningRequestEvidence) { $visibleGuiSigningRequestEvidence.stream.Dispose() }
    $postRunTrustRootEvidence.stream.Dispose()
    $visibleGuiTrustRootEvidence.stream.Dispose()
}
Write-Output "FABRIC_FEDERATION_GUI_HANDOFF_PASS|$runRoot"
