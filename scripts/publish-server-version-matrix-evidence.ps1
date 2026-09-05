[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ReportPath,

    [Parameter(Mandatory = $true)]
    [string]$BindingPath,

    [Parameter(Mandatory = $true)]
    [string]$CommitPath,

    [Parameter(Mandatory = $true)]
    [string]$ReleaseBundleRoot,

    [Parameter(Mandatory = $true)]
    [string]$ArtifactSourceCommit,

    [Parameter(Mandatory = $true)]
    [string]$SupervisorTrustRootPath,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedSupervisorTrustRootSha256,

    [string]$OutputRoot,

    [string]$EvidenceId,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repoRoot 'docs\evidence'
}
$outputRootFull = [IO.Path]::GetFullPath($OutputRoot)
$matrixDirectoryName = 'server-version-process-matrix'
$reportSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V4'
$bindingSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_BINDING_V4'
$commitSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_COMMIT_V4'
$rawManifestSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_MANIFEST_V1'
$signingRequestSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_SIGNING_REQUEST_V1'
$receiptSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_RECEIPT_V1'
$trustRootSchema = 'MCACE_SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_V1'
$indexSchema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V4'
$rawSetDomain = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_SET_V1'
$caseRuntimeDomain = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_CASE_RUNTIME_SET_V1'
$releaseArtifactDomain = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_RELEASE_ARTIFACT_SET_V1'
$matrixProductDomain = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_PRODUCT_JAR_SET_V1'
$bundleSchema = 'MCACE_RELEASE_BUNDLE_V4'
$productVersion = '0.0.1'
$targetVersions = @('1.21.11', '26.1.2', '26.2')
$maximumJsonBytes = 16777216
$maximumBundleTextBytes = 1048576
$maximumBundleArtifactBytes = 134217728
$utf8Strict = New-Object Text.UTF8Encoding($false, $true)
$utf8NoBom = New-Object Text.UTF8Encoding($false)

function Test-Sha256([object]$Value) {
    return $Value -is [string] -and [string]$Value -cmatch '^[0-9a-f]{64}$'
}

function Test-Commit([object]$Value) {
    return $Value -is [string] -and [string]$Value -cmatch '^[0-9a-f]{40}$'
}

function Test-JsonInteger([object]$Value) {
    return $Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64]
}

function Test-True([object]$Value) {
    return $Value -is [bool] -and [bool]$Value
}

function Test-StringEqual([object]$Value, [string]$Expected) {
    return $Value -is [string] -and [string]$Value -ceq $Expected
}

function Test-JsonArray([object]$Value) {
    return $Value -is [Array]
}

function Test-NonEmptyJsonString([object]$Value) {
    return $Value -is [string] -and -not [string]::IsNullOrWhiteSpace([string]$Value)
}

function Test-ExactProperties([object]$Value, [string[]]$Expected) {
    if ($null -eq $Value -or $Value -isnot [Management.Automation.PSCustomObject]) {
        return $false
    }
    $actual = [string[]]@($Value.PSObject.Properties | ForEach-Object Name)
    $wanted = [string[]]@($Expected)
    [Array]::Sort($actual, [StringComparer]::Ordinal)
    [Array]::Sort($wanted, [StringComparer]::Ordinal)
    return $actual.Count -eq $wanted.Count -and
        (($actual -join "`n") -ceq ($wanted -join "`n"))
}

function Get-BytesSha256([byte[]]$Bytes) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
}

function ConvertTo-CompactJsonBytes([object]$Value, [int]$Depth = 40) {
    return $utf8NoBom.GetBytes(($Value | ConvertTo-Json -Depth $Depth -Compress) + "`n")
}

# Matrix set commitments are a cross-process contract. The producer and the
# external supervisor signer use compact UTF-8 JSON at depth 30 without a
# trailing newline; keep file/evidence JSON newline-terminated separately.
function ConvertTo-CommitmentJsonBytes([object]$Value, [int]$Depth = 30) {
    return $utf8NoBom.GetBytes(($Value | ConvertTo-Json -Depth $Depth -Compress))
}

function Get-ApprovedMatrixSupervisorPin {
    $pin = [Environment]::GetEnvironmentVariable(
        'MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256', 'Process')
    if ([string]::IsNullOrWhiteSpace($pin) -or $pin -cnotmatch '^[0-9a-fA-F]{64}$') {
        throw 'MCACE_MATRIX_PUBLISH_APPROVED_SUPERVISOR_PIN_REQUIRED'
    }
    if ($ExpectedSupervisorTrustRootSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
            $pin.ToLowerInvariant() -cne $ExpectedSupervisorTrustRootSha256.ToLowerInvariant()) {
        throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_PIN_NOT_APPROVED'
    }
    return $pin.ToLowerInvariant()
}

function Test-FullPathBelow([string]$Root, [string]$Candidate) {
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([char[]]@('\','/')) +
        [IO.Path]::DirectorySeparatorChar
    $candidateFull = [IO.Path]::GetFullPath($Candidate)
    $comparison = if (Test-IsWindowsPlatform) {
        [StringComparison]::OrdinalIgnoreCase
    } else { [StringComparison]::Ordinal }
    return $candidateFull.StartsWith($rootFull, $comparison)
}

function Get-SetSha256([string]$Domain, [object]$Value) {
    return Get-BytesSha256 (ConvertTo-CommitmentJsonBytes ([pscustomobject][ordered]@{
        domain = $Domain
        value = $Value
    }))
}

$matrixReceiptPropertyNames = @(
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

function Get-MatrixReceiptSigningPayload([object]$Receipt) {
    $lines = [Collections.Generic.List[string]]::new()
    [void]$lines.Add('MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_RECEIPT_SIGNING_V1')
    foreach ($name in @($matrixReceiptPropertyNames | Where-Object { $_ -cne 'signature_base64' })) {
        $value = $Receipt.$name
        if ($value -is [bool]) {
            $rendered = if ([bool]$value) { 'true' } else { 'false' }
        } elseif (Test-JsonInteger $value) {
            $rendered = [Convert]::ToString($value, [Globalization.CultureInfo]::InvariantCulture)
        } else { $rendered = [string]$value }
        if ($rendered -match '[\r\n]' -or $name -match '[\r\n=]') {
            throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_SIGNING_VALUE_INVALID'
        }
        [void]$lines.Add("$name=$rendered")
    }
    return $utf8NoBom.GetBytes(($lines -join "`n") + "`n")
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

function Read-MatrixSupervisorTrustRoot([string]$PackageDirectory) {
    $approvedPin = Get-ApprovedMatrixSupervisorPin
    $rootPath = Assert-PathChainNoReparse `
        ([IO.Path]::GetFullPath($SupervisorTrustRootPath)) $true 'supervisor-trust-root'
    if (Test-FullPathBelow $repoRoot $rootPath) {
        throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_TRUST_ROOT_MUST_BE_OUT_OF_REPO'
    }
    foreach ($forbiddenRoot in @($PackageDirectory,$ReleaseBundleRoot,$outputRootFull)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$forbiddenRoot) -and
                (Test-FullPathBelow ([IO.Path]::GetFullPath($forbiddenRoot)) $rootPath)) {
            throw 'MCACE_MATRIX_PUBLISH_SELF_SUPERVISOR_TRUST_ROOT_REJECTED'
        }
    }
    $document = Read-StrictJsonDocument $rootPath 'supervisor-trust-root'
    if ([string]$document.sha256 -cne $approvedPin -or
            [string]$document.sha256 -cne $ExpectedSupervisorTrustRootSha256.ToLowerInvariant()) {
        throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_TRUST_ROOT_PIN_MISMATCH'
    }
    $root = $document.value
    if (-not (Test-ExactProperties $root @(
            'schema','artifact_class','key_id','algorithm','modulus_base64',
            'exponent_base64','test_fixture')) -or
            [string]$root.schema -cne $trustRootSchema -or
            [string]$root.artifact_class -cne 'OUT_OF_BAND_PINNED_MATRIX_SUPERVISOR_TRUST_ROOT' -or
            [string]$root.key_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$' -or
            [string]$root.algorithm -cne 'RSA_PKCS1_SHA256' -or
            $root.test_fixture -isnot [bool] -or [bool]$root.test_fixture) {
        throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_TRUST_ROOT_INVALID'
    }
    try {
        $modulus = [Convert]::FromBase64String([string]$root.modulus_base64)
        $exponent = [Convert]::FromBase64String([string]$root.exponent_base64)
    } catch { throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_TRUST_ROOT_KEY_ENCODING_INVALID' }
    if ($modulus.Length -lt 256 -or $modulus.Length -gt 512 -or
            $exponent.Length -lt 1 -or $exponent.Length -gt 4) {
        throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_TRUST_ROOT_KEY_SIZE_INVALID'
    }
    return [pscustomobject]@{
        document=$document; value=$root; modulus=$modulus; exponent=$exponent
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

function Assert-NoAmbiguousJsonProperties([object]$Value) {
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return }
    if ($Value -is [Collections.IDictionary]) {
        $names = @($Value.Keys | ForEach-Object { [string]$_ })
        if (@($names | Group-Object { $_.ToLowerInvariant() } | Where-Object Count -gt 1).Count -gt 0) {
            throw 'MCACE_MATRIX_PUBLISH_JSON_CASE_AMBIGUOUS_PROPERTY'
        }
        foreach ($key in @($Value.Keys)) { Assert-NoAmbiguousJsonProperties $Value[$key] }
        return
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $properties = @($Value.PSObject.Properties)
        $names = @($properties | ForEach-Object Name)
        if (@($names | Group-Object { $_.ToLowerInvariant() } | Where-Object Count -gt 1).Count -gt 0) {
            throw 'MCACE_MATRIX_PUBLISH_JSON_CASE_AMBIGUOUS_PROPERTY'
        }
        foreach ($property in $properties) { Assert-NoAmbiguousJsonProperties $property.Value }
        return
    }
    if ($Value -is [Collections.IEnumerable]) {
        foreach ($item in $Value) { Assert-NoAmbiguousJsonProperties $item }
    }
}

function Assert-NoSecretFieldsOrAbsoluteStrings([object]$Value, [string]$Role) {
    if ($null -eq $Value -or $Value -is [ValueType]) { return }
    if ($Value -is [string]) {
        $text = [string]$Value
        if ($text -cmatch '^[A-Za-z]:[\\/]' -or $text.StartsWith('\\', [StringComparison]::Ordinal) -or
                ($text.StartsWith('/', [StringComparison]::Ordinal) -and
                 -not $text.StartsWith('//', [StringComparison]::Ordinal))) {
            throw "MCACE_MATRIX_PUBLISH_ABSOLUTE_PATH_REJECTED|$Role"
        }
        if ($text -match '(?i)(?:password|passwd|client[_-]?secret|access[_-]?token|private[_-]?key)\s*[:=]') {
            throw "MCACE_MATRIX_PUBLISH_SECRET_VALUE_REJECTED|$Role"
        }
        return
    }
    if ($Value -is [Collections.IDictionary]) {
        foreach ($key in @($Value.Keys)) {
            $name = ([string]$key).ToLowerInvariant()
            if ($name -match '(^|_)(password|passwd|secret|token|credential|credentials|cookie|authorization|api_key|access_key|client_secret|private_key)(_|$)') {
                throw "MCACE_MATRIX_PUBLISH_SECRET_FIELD_REJECTED|$Role|$key"
            }
            Assert-NoSecretFieldsOrAbsoluteStrings $Value[$key] $Role
        }
        return
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        foreach ($property in @($Value.PSObject.Properties)) {
            $name = ([string]$property.Name).ToLowerInvariant()
            if ($name -match '(^|_)(password|passwd|secret|token|credential|credentials|cookie|authorization|api_key|access_key|client_secret|private_key)(_|$)') {
                throw "MCACE_MATRIX_PUBLISH_SECRET_FIELD_REJECTED|$Role|$($property.Name)"
            }
            Assert-NoSecretFieldsOrAbsoluteStrings $property.Value $Role
        }
        return
    }
    if ($Value -is [Collections.IEnumerable]) {
        foreach ($item in $Value) { Assert-NoSecretFieldsOrAbsoluteStrings $item $Role }
    }
}

function ConvertFrom-StrictJson([string]$Raw, [string]$Role) {
    # Matrix evidence documents are newline-terminated.  The detached receipt
    # and the out-of-band trust root are deliberate compact-JSON exceptions:
    # the authority emits those bytes without a trailing LF, and the producer
    # binds the receipt bytes in commit.json while the trust-root file is
    # pinned by its raw SHA-256.  Keep the exceptions role-scoped so a caller
    # cannot weaken the canonical encoding of any other published document.
    $isCompactAuthorityJson = $Role -in @('supervisor-receipt','supervisor-trust-root')
    $hasTrailingNewline = $Raw.EndsWith("`n", [StringComparison]::Ordinal)
    if ([string]::IsNullOrWhiteSpace($Raw) -or $Raw.Contains("`r") -or
            (-not $isCompactAuthorityJson -and -not $hasTrailingNewline)) {
        throw "MCACE_MATRIX_PUBLISH_JSON_CANONICAL_ENCODING_INVALID|$Role"
    }
    $body = if ($hasTrailingNewline) {
        $Raw.Substring(0, $Raw.Length - 1)
    } else {
        $Raw
    }
    if ($body.Contains("`n") -or $body.Length -lt 2 -or
            $body[0] -cne '{' -or $body[$body.Length - 1] -cne '}') {
        throw "MCACE_MATRIX_PUBLISH_JSON_CANONICAL_OBJECT_REQUIRED|$Role"
    }
    $propertyMatches = [regex]::Matches(
        $body,
        '(?:\{|,)\s*"(?<name>(?:\\["\\/bfnrt]|\\u[0-9a-fA-F]{4}|[^"\\])*)"\s*:',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $seenPropertyCase = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $hasCaseVariantPropertyName = $false
    foreach ($propertyMatch in $propertyMatches) {
        $propertyName = [string]$propertyMatch.Groups['name'].Value
        if ($seenPropertyCase.ContainsKey($propertyName)) {
            if ([string]$seenPropertyCase[$propertyName] -cne $propertyName) {
                $hasCaseVariantPropertyName = $true
            }
        } else {
            $seenPropertyCase.Add($propertyName, $propertyName)
        }
    }
    try {
        $command = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
        if ($command.Parameters.ContainsKey('DateKind')) {
            $value = ConvertFrom-Json -InputObject $body -DateKind String -ErrorAction Stop
        } else {
            $value = ConvertFrom-Json -InputObject $body -ErrorAction Stop
        }
    } catch {
        $jsonFailure = [string]$_.Exception.Message
        $jsonFailureId = [string]$_.FullyQualifiedErrorId
        if ($jsonFailureId.StartsWith(
                'DuplicateKeysInJsonString', [StringComparison]::Ordinal)) {
            if ($hasCaseVariantPropertyName) {
                throw "MCACE_MATRIX_PUBLISH_JSON_CASE_AMBIGUOUS_PROPERTY|$Role"
            }
            throw "MCACE_MATRIX_PUBLISH_JSON_DUPLICATE_PROPERTY|$Role"
        }
        if ($jsonFailure -match "(?i)duplicated keys '([^']+)' and '([^']+)'") {
            $firstKey = [string]$Matches[1]
            $secondKey = [string]$Matches[2]
            if (-not $firstKey.Equals($secondKey, [StringComparison]::Ordinal) -and
                    $firstKey.Equals($secondKey, [StringComparison]::OrdinalIgnoreCase)) {
                throw "MCACE_MATRIX_PUBLISH_JSON_CASE_AMBIGUOUS_PROPERTY|$Role"
            }
            throw "MCACE_MATRIX_PUBLISH_JSON_DUPLICATE_PROPERTY|$Role"
        }
        if ($jsonFailure -match '(?i)different casing|existing key.+attempted') {
            throw "MCACE_MATRIX_PUBLISH_JSON_CASE_AMBIGUOUS_PROPERTY|$Role"
        }
        if ($jsonFailure -match '(?i)duplicat(?:e|ed) (?:json )?(?:object )?(?:key|propert)') {
            throw "MCACE_MATRIX_PUBLISH_JSON_DUPLICATE_PROPERTY|$Role"
        }
        throw "MCACE_MATRIX_PUBLISH_JSON_INVALID|$Role"
    }
    $propertyTokens = $propertyMatches.Count
    if ($propertyTokens -ne (Get-JsonGraphPropertyCount $value)) {
        throw "MCACE_MATRIX_PUBLISH_JSON_DUPLICATE_PROPERTY|$Role"
    }
    Assert-NoAmbiguousJsonProperties $value
    Assert-NoSecretFieldsOrAbsoluteStrings $value $Role
    return $value
}

function ConvertFrom-StrictRawJson([string]$Raw, [string]$Role) {
    if ([string]::IsNullOrWhiteSpace($Raw) -or $Raw.IndexOf([char]0) -ge 0) {
        throw "MCACE_MATRIX_PUBLISH_RAW_JSON_INVALID|$Role"
    }
    $propertyMatches = [regex]::Matches(
        $Raw,
        '(?:\{|,)\s*"(?<name>(?:\\["\\/bfnrt]|\\u[0-9a-fA-F]{4}|[^"\\])*)"\s*:',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $seen = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($match in $propertyMatches) {
        $name = [string]$match.Groups['name'].Value
        if ($seen.ContainsKey($name)) {
            if ([string]$seen[$name] -cne $name) {
                throw "MCACE_MATRIX_PUBLISH_JSON_CASE_AMBIGUOUS_PROPERTY|$Role"
            }
            throw "MCACE_MATRIX_PUBLISH_JSON_DUPLICATE_PROPERTY|$Role"
        }
        $seen.Add($name,$name)
    }
    try {
        $command = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
        if ($command.Parameters.ContainsKey('DateKind')) {
            $value = ConvertFrom-Json -InputObject $Raw -DateKind String -ErrorAction Stop
        } else { $value = ConvertFrom-Json -InputObject $Raw -ErrorAction Stop }
    } catch {
        throw "MCACE_MATRIX_PUBLISH_RAW_JSON_INVALID|$Role"
    }
    if ($value -isnot [Management.Automation.PSCustomObject] -or
            $propertyMatches.Count -ne (Get-JsonGraphPropertyCount $value)) {
        throw "MCACE_MATRIX_PUBLISH_JSON_DUPLICATE_PROPERTY|$Role"
    }
    Assert-NoAmbiguousJsonProperties $value
    Assert-NoSecretFieldsOrAbsoluteStrings $value $Role
    return $value
}

function Assert-NoSyntheticMarkers([object]$Value, [string]$Role) {
    if ($null -eq $Value -or $Value -is [ValueType]) { return }
    if ($Value -is [string]) {
        if ([string]$Value -match '(?i)(?:^|[^a-z0-9])(synthetic|test[_-]?fixture|manual[_-]?byte[_-]?array)(?:$|[^a-z0-9])') {
            throw "MCACE_MATRIX_PUBLISH_SYNTHETIC_EVIDENCE_REJECTED|$Role"
        }
        return
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        foreach ($property in @($Value.PSObject.Properties)) {
            if ([string]$property.Name -match '(?i)synthetic|test[_-]?fixture') {
                throw "MCACE_MATRIX_PUBLISH_SYNTHETIC_EVIDENCE_REJECTED|$Role"
            }
            Assert-NoSyntheticMarkers $property.Value $Role
        }
        return
    }
    if ($Value -is [Collections.IDictionary]) {
        foreach ($key in @($Value.Keys)) { Assert-NoSyntheticMarkers $Value[$key] $Role }
        return
    }
    if ($Value -is [Collections.IEnumerable]) {
        foreach ($item in $Value) { Assert-NoSyntheticMarkers $item $Role }
    }
}

function Test-IsWindowsPlatform {
    if (Get-Variable IsWindows -ErrorAction SilentlyContinue) { return [bool]$IsWindows }
    return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

function Initialize-MatrixPublisherFileIdentityApi {
    if (-not (Test-IsWindowsPlatform) -or
            ('MCAceMatrixPublisherFileIdentityV1' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class MCAceMatrixPublisherFileIdentityV1 {
    private const uint FILE_READ_ATTRIBUTES = 0x80;
    private const uint FILE_SHARE_READ = 0x1;
    private const uint FILE_SHARE_WRITE = 0x2;
    private const uint FILE_SHARE_DELETE = 0x4;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
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
    private static string Validate(INFO i, bool directory) {
        if ((i.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            throw new InvalidOperationException("reparse point rejected");
        bool actualDirectory = (i.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (actualDirectory != directory)
            throw new InvalidOperationException(directory ? "directory required" : "regular file required");
        return Describe(i);
    }
    public static string NoFollow(string path, bool directory) {
        uint flags = FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0u);
        using (SafeFileHandle h = CreateFileW(path, FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero)) {
            if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            INFO i; if (!GetFileInformationByHandle(h, out i))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return Validate(i, directory);
        }
    }
    public static string FromHandle(SafeFileHandle h, bool directory) {
        INFO i; if (!GetFileInformationByHandle(h, out i))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return Validate(i, directory);
    }
}
'@
}

function Get-MatrixPublisherNoFollowIdentity([string]$Path, [switch]$Directory) {
    if (Test-IsWindowsPlatform) {
        Initialize-MatrixPublisherFileIdentityApi
        try { return [MCAceMatrixPublisherFileIdentityV1]::NoFollow($Path, [bool]$Directory) }
        catch { throw "MCACE_MATRIX_PUBLISH_NOFOLLOW_IDENTITY_FAILED|$($_.Exception.Message)" }
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($item.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $item.LinkType) -or
            [bool]$item.PSIsContainer -ne [bool]$Directory) {
        throw 'MCACE_MATRIX_PUBLISH_NOFOLLOW_REGULAR_TYPE_REJECTED'
    }
    return "portable:$($item.FullName):$([long]$item.Length):$($item.LastWriteTimeUtc.Ticks)"
}

function Assert-LocalPath([string]$FullPath, [string]$Role) {
    if ((Test-IsWindowsPlatform) -and
            ($FullPath.StartsWith('\\', [StringComparison]::Ordinal) -or
             $FullPath.StartsWith('//', [StringComparison]::Ordinal))) {
        throw "MCACE_MATRIX_PUBLISH_NETWORK_PATH_REJECTED|$Role"
    }
    $existing = $FullPath
    while (-not (Test-Path -LiteralPath $existing)) {
        $parent = Split-Path -Path $existing -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $existing) {
            throw "MCACE_MATRIX_PUBLISH_PATH_PARENT_MISSING|$Role"
        }
        $existing = $parent
    }
    $item = Get-Item -LiteralPath $existing -Force -ErrorAction Stop
    if ($null -ne $item.PSDrive -and -not [string]::IsNullOrWhiteSpace([string]$item.PSDrive.DisplayRoot)) {
        throw "MCACE_MATRIX_PUBLISH_NETWORK_DRIVE_REJECTED|$Role"
    }
}

function Assert-PathChainNoReparse([string]$FullPath, [bool]$LeafMustExist, [string]$Role) {
    $full = [IO.Path]::GetFullPath($FullPath)
    Assert-LocalPath $full $Role
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root)) { throw "MCACE_MATRIX_PUBLISH_PATH_ROOT_INVALID|$Role" }
    $relative = $full.Substring($root.Length)
    $segments = @($relative.Split(
        @([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar),
        [StringSplitOptions]::RemoveEmptyEntries))
    $cursor = $root
    for ($index = 0; $index -lt $segments.Count; $index++) {
        $cursor = Join-Path $cursor $segments[$index]
        if (-not (Test-Path -LiteralPath $cursor)) {
            if ($LeafMustExist -or $index -lt ($segments.Count - 1)) {
                throw "MCACE_MATRIX_PUBLISH_PATH_COMPONENT_MISSING|$Role"
            }
            return $full
        }
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($item.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $item.LinkType)) {
            throw "MCACE_MATRIX_PUBLISH_REPARSE_PATH_REJECTED|$Role"
        }
    }
    return $full
}

function Read-LockedFileBytes(
        [string]$Path,
        [long]$MinimumBytes,
        [long]$MaximumBytes,
        [string]$Role) {
    $full = Assert-PathChainNoReparse ([IO.Path]::GetFullPath($Path)) $true $Role
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "MCACE_MATRIX_PUBLISH_FILE_REQUIRED|$Role"
    }
    $beforeIdentity = Get-MatrixPublisherNoFollowIdentity $full
    $before = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "MCACE_MATRIX_PUBLISH_REPARSE_FILE_REJECTED|$Role"
    }
    $stream = New-Object IO.FileStream(
        $full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        if (Test-IsWindowsPlatform) {
            try { $handleIdentity = [MCAceMatrixPublisherFileIdentityV1]::FromHandle($stream.SafeFileHandle, $false) }
            catch { throw "MCACE_MATRIX_PUBLISH_HANDLE_IDENTITY_FAILED|$Role|$($_.Exception.Message)" }
            if ($handleIdentity -cne $beforeIdentity) {
                throw "MCACE_MATRIX_PUBLISH_HANDLE_IDENTITY_CHANGED|$Role"
            }
        }
        $length = [long]$stream.Length
        if ($length -lt $MinimumBytes -or $length -gt $MaximumBytes -or $length -gt [int]::MaxValue) {
            throw "MCACE_MATRIX_PUBLISH_FILE_SIZE_INVALID|$Role|$length"
        }
        $bytes = New-Object byte[] ([int]$length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw "MCACE_MATRIX_PUBLISH_SHORT_READ|$Role" }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1 -or $stream.Length -ne $length) {
            throw "MCACE_MATRIX_PUBLISH_FILE_CHANGED_DURING_READ|$Role"
        }
        $stream.Position = 0
        $second = New-Object byte[] ([int]$length)
        $secondOffset = 0
        while ($secondOffset -lt $second.Length) {
            $read = $stream.Read($second, $secondOffset, $second.Length - $secondOffset)
            if ($read -le 0) { throw "MCACE_MATRIX_PUBLISH_SHORT_READ|$Role|second" }
            $secondOffset += $read
        }
        if ((Get-BytesSha256 $second) -cne (Get-BytesSha256 $bytes)) {
            throw "MCACE_MATRIX_PUBLISH_LOCKED_DOUBLE_READ_MISMATCH|$Role"
        }
    } finally {
        $stream.Dispose()
    }
    $after = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    $null = Assert-PathChainNoReparse $full $true $Role
    if ((Get-MatrixPublisherNoFollowIdentity $full) -cne $beforeIdentity -or
            [long]$before.Length -ne [long]$after.Length -or
            $before.LastWriteTimeUtc.Ticks -ne $after.LastWriteTimeUtc.Ticks -or
            [long]$after.Length -ne [long]$bytes.Length) {
        throw "MCACE_MATRIX_PUBLISH_FILE_CHANGED_DURING_READ|$Role"
    }
    return [pscustomobject]@{
        path = $full
        bytes = $bytes
        size_bytes = [long]$bytes.Length
        sha256 = Get-BytesSha256 $bytes
    }
}

function Read-StrictJsonDocument([string]$Path, [string]$Role) {
    $document = Read-LockedFileBytes $Path 3 $maximumJsonBytes $Role
    if ($document.bytes.Length -ge 3 -and $document.bytes[0] -eq 0xef -and
            $document.bytes[1] -eq 0xbb -and $document.bytes[2] -eq 0xbf) {
        throw "MCACE_MATRIX_PUBLISH_JSON_BOM_REJECTED|$Role"
    }
    try { $raw = $utf8Strict.GetString($document.bytes) }
    catch { throw "MCACE_MATRIX_PUBLISH_JSON_UTF8_INVALID|$Role" }
    $value = ConvertFrom-StrictJson $raw $Role
    $document | Add-Member -NotePropertyName raw -NotePropertyValue $raw
    $document | Add-Member -NotePropertyName value -NotePropertyValue $value
    return $document
}

function Read-StrictRawJsonDocument([string]$Path, [string]$Role) {
    $document = Read-LockedFileBytes $Path 3 $maximumJsonBytes $Role
    if ($document.bytes.Length -ge 3 -and $document.bytes[0] -eq 0xef -and
            $document.bytes[1] -eq 0xbb -and $document.bytes[2] -eq 0xbf) {
        throw "MCACE_MATRIX_PUBLISH_JSON_BOM_REJECTED|$Role"
    }
    try { $raw = $utf8Strict.GetString($document.bytes) }
    catch { throw "MCACE_MATRIX_PUBLISH_JSON_UTF8_INVALID|$Role" }
    $value = ConvertFrom-StrictRawJson $raw $Role
    Assert-NoSyntheticMarkers $value $Role
    $document | Add-Member -NotePropertyName raw -NotePropertyValue $raw
    $document | Add-Member -NotePropertyName value -NotePropertyValue $value
    return $document
}

function ConvertTo-EvidenceTime([object]$Value, [string]$Role) {
    try {
        if ($Value -is [DateTimeOffset]) {
            return ([DateTimeOffset]$Value).ToUniversalTime()
        }
        if ($Value -is [DateTime]) {
            return ([DateTimeOffset]([DateTime]$Value)).ToUniversalTime()
        }
        if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Value)) {
            throw 'invalid'
        }
        return [DateTimeOffset]::Parse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    } catch {
        throw "MCACE_MATRIX_PUBLISH_TIMESTAMP_INVALID|$Role"
    }
}

function Assert-SameTime([object]$Left, [object]$Right, [string]$Role) {
    if ((ConvertTo-EvidenceTime $Left "$Role.left").Ticks -ne
            (ConvertTo-EvidenceTime $Right "$Role.right").Ticks) {
        throw "MCACE_MATRIX_PUBLISH_TIMESTAMP_MISMATCH|$Role"
    }
}

function Assert-CanonicalRelativePath([object]$Value, [string]$Role) {
    if ($Value -isnot [string]) { throw "MCACE_MATRIX_PUBLISH_RELATIVE_PATH_INVALID|$Role" }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text) -or $text.IndexOf('\') -ge 0 -or
            $text.StartsWith('/', [StringComparison]::Ordinal) -or
            $text -cmatch '^[A-Za-z]:' -or $text.IndexOf('//') -ge 0 -or
            $text -cmatch '(^|/)\.{1,2}($|/)' -or $text -cne $text.Normalize()) {
        throw "MCACE_MATRIX_PUBLISH_RELATIVE_PATH_INVALID|$Role"
    }
}

function Get-ExpectedCases {
    $list = New-Object 'Collections.Generic.List[object]'
    foreach ($version in $targetVersions) {
        foreach ($backend in @('PAPER', 'FOLIA')) {
            foreach ($proxy in @('VELOCITY', 'BUNGEE')) {
                $protocol = if ($version -ceq '1.21.11') { 774 } elseif ($version -ceq '26.1.2') { 775 } else { 776 }
                $java = if ($version -ceq '1.21.11') { 21 } else { 25 }
                $lane = if ($version -ceq '26.2' -and $backend -ceq 'FOLIA') { 'BETA' } else { 'STABLE' }
                $proxyId = if ($proxy -ceq 'VELOCITY') { 'velocity' } else { 'bungee' }
                $backendId = $backend.ToLowerInvariant()
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
                [void]$list.Add([pscustomobject][ordered]@{
                    case_id = "$version-$backendId-$proxyId"
                    minecraft_version = $version
                    minecraft_protocol = $protocol
                    server_java_feature = $java
                    backend = $backend
                    proxy = $proxy
                    lane = $lane
                    selector = $selector
                })
            }
        }
    }
    return $list.ToArray()
}

function Get-OrderedRawReportSetSha256([object[]]$Descriptors) {
    $records = @($Descriptors | ForEach-Object {
        [pscustomobject][ordered]@{
            ordinal=[int]$_.ordinal; case_id=[string]$_.case_id; path=[string]$_.path
            sha256=[string]$_.sha256; size_bytes=[long]$_.size_bytes
        }
    })
    return Get-BytesSha256 (ConvertTo-CompactJsonBytes ([pscustomobject][ordered]@{
        domain=$rawSetDomain; source_commit=$ArtifactSourceCommit; reports=$records
    }))
}

function Assert-RawCaseDocument([object]$Raw, [object]$Case, [object]$Expected) {
    $names = @('schema','proxy','backend_platform','backend_minecraft_version','forwarding_mode',
        'forwarding_configured','proxy_port','backend_port','tcp_connected','login_success',
        'compression_seen','configuration_finished','mcace_server_hello','mcace_auth_result',
        'mcace_auth_accepted','backend_admission','backend_context_shadow_audit','channels',
        'packet_trace','limitations','cleanup_process_ids','remaining_run_processes')
    $forwarding = if ([string]$Expected.proxy -ceq 'VELOCITY') {
        'velocity-modern'
    } else { 'bungee-ip-forwarding' }
    if (-not (Test-ExactProperties $Raw $names) -or
            -not (Test-JsonInteger $Raw.schema) -or [int]$Raw.schema -ne 4 -or
            [string]$Raw.proxy -cne [string]$Expected.proxy -or
            [string]$Raw.backend_platform -cne [string]$Expected.backend -or
            [string]$Raw.backend_minecraft_version -cne [string]$Expected.minecraft_version -or
            [string]$Raw.forwarding_mode -cne $forwarding -or
            -not (Test-JsonInteger $Raw.proxy_port) -or [int]$Raw.proxy_port -lt 1 -or
            [int]$Raw.proxy_port -gt 65535 -or -not (Test-JsonInteger $Raw.backend_port) -or
            [int]$Raw.backend_port -lt 1 -or [int]$Raw.backend_port -gt 65535 -or
            [int]$Raw.proxy_port -eq [int]$Raw.backend_port) {
        throw "MCACE_MATRIX_PUBLISH_RAW_IDENTITY_INVALID|$($Expected.case_id)"
    }
    foreach ($name in @('forwarding_configured','tcp_connected','login_success','compression_seen',
            'configuration_finished','mcace_server_hello','mcace_auth_result','mcace_auth_accepted',
            'backend_admission','backend_context_shadow_audit')) {
        if (-not (Test-True $Raw.$name)) {
            throw "MCACE_MATRIX_PUBLISH_RAW_ASSERTION_FAILED|$($Expected.case_id)|$name"
        }
    }
    $cleanupIds = @($Raw.cleanup_process_ids)
    if (@($Raw.limitations).Count -ne 0 -or @($Raw.remaining_run_processes).Count -ne 0 -or
            $cleanupIds.Count -lt 2 -or @($cleanupIds | Where-Object {
                -not (Test-JsonInteger $_) -or [long]$_ -le 0
            }).Count -ne 0 -or @($cleanupIds | Select-Object -Unique).Count -ne $cleanupIds.Count -or
            $cleanupIds.Count -ne [int]$Case.cleanup_process_count) {
        throw "MCACE_MATRIX_PUBLISH_RAW_CLEANUP_INVALID|$($Expected.case_id)"
    }
    $playId = if ([string]$Expected.minecraft_version -ceq '1.21.11') { '0x30' } else { '0x31' }
    if (@($Raw.channels | Where-Object { [string]$_ -ceq 'mcace:handshake' }).Count -lt 1 -or
            @($Raw.packet_trace | Where-Object { [string]$_ -ceq "PLAY:$playId" }).Count -ne 1) {
        throw "MCACE_MATRIX_PUBLISH_RAW_PROTOCOL_INVALID|$($Expected.case_id)"
    }
}

function Assert-RawEvidencePackage(
        [object]$ManifestDocument,
        [object]$Report,
        [string]$PackageDirectory) {
    $manifest = $ManifestDocument.value
    $names = @('schema','generated_at','source_mode','source_commit','product_version',
        'case_count','ordered_raw_report_set_sha256','reports')
    if (-not (Test-ExactProperties $manifest $names) -or
            [string]$manifest.schema -cne $rawManifestSchema -or
            [string]$manifest.source_mode -cne 'EXECUTED' -or
            [string]$manifest.source_commit -cne $ArtifactSourceCommit -or
            [string]$manifest.product_version -cne $productVersion -or
            -not (Test-JsonInteger $manifest.case_count) -or [int]$manifest.case_count -ne 12 -or
            -not (Test-Sha256 $manifest.ordered_raw_report_set_sha256) -or
            -not (Test-JsonArray $manifest.reports) -or @($manifest.reports).Count -ne 12) {
        throw 'MCACE_MATRIX_PUBLISH_RAW_MANIFEST_INVALID'
    }
    Assert-SameTime $manifest.generated_at $Report.generated_at 'raw-manifest.generated_at'
    $rawRoot = Assert-PathChainNoReparse (Join-Path $PackageDirectory 'raw') $true 'raw-root'
    if (-not (Test-Path -LiteralPath $rawRoot -PathType Container)) {
        throw 'MCACE_MATRIX_PUBLISH_RAW_DIRECTORY_REQUIRED'
    }
    $rawEntries = @(Get-ChildItem -LiteralPath $rawRoot -Force -ErrorAction Stop)
    if ($rawEntries.Count -ne 12 -or @($rawEntries | Where-Object {
                $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
            }).Count -ne 0) {
        throw 'MCACE_MATRIX_PUBLISH_RAW_EXACT_12_FILES_REQUIRED'
    }
    $descriptorNames = @('ordinal','case_id','path','sha256','size_bytes','raw_schema',
        'minecraft_version','backend','proxy','execution_mode','invocation_exit_code',
        'invocation_log_sha256','cleanup_process_count','remaining_run_process_count',
        'process_cleanup_observed')
    $expectedCases = @(Get-ExpectedCases)
    $cases = @($Report.cases)
    $documents = [Collections.Generic.List[object]]::new()
    for ($index=0; $index -lt 12; $index++) {
        $descriptor = @($manifest.reports)[$index]
        $case = $cases[$index]
        $expected = $expectedCases[$index]
        $expectedPath = "raw/$($expected.case_id).json"
        if (-not (Test-ExactProperties $descriptor $descriptorNames) -or
                -not (Test-JsonInteger $descriptor.ordinal) -or [int]$descriptor.ordinal -ne ($index+1) -or
                [string]$descriptor.case_id -cne [string]$expected.case_id -or
                [string]$descriptor.path -cne $expectedPath -or
                -not (Test-Sha256 $descriptor.sha256) -or
                -not (Test-JsonInteger $descriptor.size_bytes) -or [long]$descriptor.size_bytes -le 0 -or
                [int]$descriptor.raw_schema -ne 4 -or
                [string]$descriptor.minecraft_version -cne [string]$expected.minecraft_version -or
                [string]$descriptor.backend -cne [string]$expected.backend -or
                [string]$descriptor.proxy -cne [string]$expected.proxy -or
                [string]$descriptor.execution_mode -cne 'EXECUTE' -or
                -not (Test-JsonInteger $descriptor.invocation_exit_code) -or [int]$descriptor.invocation_exit_code -ne 0 -or
                -not (Test-Sha256 $descriptor.invocation_log_sha256) -or
                [int]$descriptor.cleanup_process_count -ne [int]$case.cleanup_process_count -or
                [int]$descriptor.remaining_run_process_count -ne 0 -or
                -not (Test-True $descriptor.process_cleanup_observed) -or
                [string]$case.raw_report -cne $expectedPath -or
                [string]$case.raw_report_sha256 -cne [string]$descriptor.sha256 -or
                [long]$case.raw_report_size -ne [long]$descriptor.size_bytes -or
                [string]$case.invocation_log_sha256 -cne [string]$descriptor.invocation_log_sha256) {
            throw "MCACE_MATRIX_PUBLISH_RAW_DESCRIPTOR_INVALID|$($expected.case_id)"
        }
        $document = Read-StrictRawJsonDocument `
            (Join-Path $PackageDirectory ($expectedPath.Replace('/','\'))) "raw-$($expected.case_id)"
        if ([string]$document.sha256 -cne [string]$descriptor.sha256 -or
                [long]$document.size_bytes -ne [long]$descriptor.size_bytes) {
            throw "MCACE_MATRIX_PUBLISH_RAW_BYTES_MISMATCH|$($expected.case_id)"
        }
        Assert-RawCaseDocument $document.value $case $expected
        [void]$documents.Add($document)
    }
    $ordered = Get-OrderedRawReportSetSha256 @($manifest.reports)
    if ([string]$manifest.ordered_raw_report_set_sha256 -cne $ordered -or
            [string]$Report.ordered_raw_report_set_sha256 -cne $ordered -or
            [string]$Report.raw_manifest_sha256 -cne [string]$ManifestDocument.sha256 -or
            [long]$Report.raw_manifest_bytes -ne [long]$ManifestDocument.size_bytes) {
        throw 'MCACE_MATRIX_PUBLISH_RAW_SET_BINDING_INVALID'
    }
    return [pscustomobject]@{
        manifest=$manifest; manifest_document=$ManifestDocument
        reports=@($manifest.reports); documents=$documents.ToArray(); ordered_sha256=$ordered
    }
}

function Assert-ProductDescriptor([object]$Descriptor, [string]$Role, [string]$ExpectedRelative) {
    if (-not (Test-ExactProperties $Descriptor @('relative','sha256','size')) -or
            [string]$Descriptor.relative -cne $ExpectedRelative -or
            -not (Test-Sha256 $Descriptor.sha256) -or
            -not (Test-JsonInteger $Descriptor.size) -or [long]$Descriptor.size -le 0) {
        throw "MCACE_MATRIX_PUBLISH_PRODUCT_DESCRIPTOR_INVALID|$Role"
    }
}

function Assert-CurrentBinding([object]$Current, [object]$Report) {
    $names = @(
        'source_commit','product_version','target_versions','case_count',
        'source_manifest_sha256','source_file_count','wrapper_sha256','wrapper_test_sha256',
        'runtime_assets_manifest_sha256','prepared_manifest_sha256','assets','prepared_trees',
        'root_jdk','server_jdks','gradle','product_jars','definitions')
    if (-not (Test-ExactProperties $Current $names) -or
            -not (Test-StringEqual $Current.source_commit $ArtifactSourceCommit) -or
            -not (Test-StringEqual $Current.product_version $productVersion) -or
            -not (Test-JsonArray $Current.target_versions) -or
            ((@($Current.target_versions) -join ',') -cne ($targetVersions -join ',')) -or
            -not (Test-JsonInteger $Current.case_count) -or [int]$Current.case_count -ne 12 -or
            -not (Test-Sha256 $Current.source_manifest_sha256) -or
            -not (Test-JsonInteger $Current.source_file_count) -or [int]$Current.source_file_count -lt 20 -or
            -not (Test-Sha256 $Current.wrapper_sha256) -or
            -not (Test-Sha256 $Current.wrapper_test_sha256) -or
            -not (Test-Sha256 $Current.runtime_assets_manifest_sha256) -or
            -not (Test-Sha256 $Current.prepared_manifest_sha256) -or
            -not (Test-JsonArray $Current.assets) -or @($Current.assets).Count -ne 8 -or
            -not (Test-JsonArray $Current.prepared_trees) -or @($Current.prepared_trees).Count -ne 6 -or
            -not (Test-JsonArray $Current.server_jdks) -or @($Current.server_jdks).Count -ne 2 -or
            -not (Test-JsonArray $Current.definitions) -or @($Current.definitions).Count -ne 12) {
        throw 'MCACE_MATRIX_PUBLISH_CURRENT_BINDING_INVALID'
    }

    $assetNames = @('project','version','build','sha256','size','channel','java_major')
    $assetMap = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($asset in @($Current.assets)) {
        if (-not (Test-ExactProperties $asset $assetNames) -or
                [string]$asset.project -notin @('paper','folia','velocity','bungeecord') -or
                -not (Test-NonEmptyJsonString $asset.version) -or
                [string]$asset.build -cnotmatch '^[0-9]+$' -or
                -not (Test-Sha256 $asset.sha256) -or
                -not (Test-JsonInteger $asset.size) -or [long]$asset.size -le 0 -or
                -not (Test-JsonInteger $asset.java_major)) {
            throw 'MCACE_MATRIX_PUBLISH_ASSET_INVALID'
        }
        $project = [string]$asset.project
        $version = [string]$asset.version
        $key = "$project|$version"
        if ($assetMap.ContainsKey($key)) {
            throw "MCACE_MATRIX_PUBLISH_ASSET_DUPLICATE|$key"
        }
        if ($project -in @('paper','folia')) {
            $expectedJava = if ($version -ceq '1.21.11') { 21 } else { 25 }
            $expectedChannel = if ($project -ceq 'folia' -and $version -ceq '26.2') {
                'BETA'
            } else { 'STABLE' }
            if ($version -notin $targetVersions -or
                    [int]$asset.java_major -ne $expectedJava -or
                    -not (Test-StringEqual $asset.channel $expectedChannel)) {
                throw "MCACE_MATRIX_PUBLISH_BACKEND_ASSET_IDENTITY_INVALID|$key"
            }
        } else {
            if (($project -ceq 'velocity' -and $version -cne '3.5.1-615') -or
                    ($project -ceq 'bungeecord' -and $version -cne '2085') -or
                    [int]$asset.java_major -ne 21 -or
                    -not (Test-StringEqual $asset.channel 'REVIEWED')) {
                throw "MCACE_MATRIX_PUBLISH_PROXY_ASSET_IDENTITY_INVALID|$key"
            }
        }
        $assetMap.Add($key, $asset)
    }
    $expectedAssetKeys = @(
        'paper|1.21.11','paper|26.1.2','paper|26.2',
        'folia|1.21.11','folia|26.1.2','folia|26.2',
        'velocity|3.5.1-615','bungeecord|2085')
    foreach ($key in $expectedAssetKeys) {
        if (-not $assetMap.ContainsKey($key)) {
            throw "MCACE_MATRIX_PUBLISH_ASSET_MISSING|$key"
        }
    }

    $preparedNames = @(
        'project','version','build','server_sha256','prepared_tree_sha256',
        'file_count','total_size')
    $preparedMap = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($prepared in @($Current.prepared_trees)) {
        if (-not (Test-ExactProperties $prepared $preparedNames) -or
                [string]$prepared.project -notin @('paper','folia') -or
                [string]$prepared.version -notin $targetVersions -or
                [string]$prepared.build -cnotmatch '^[0-9]+$' -or
                -not (Test-Sha256 $prepared.server_sha256) -or
                -not (Test-Sha256 $prepared.prepared_tree_sha256) -or
                -not (Test-JsonInteger $prepared.file_count) -or
                [int]$prepared.file_count -le 0 -or
                -not (Test-JsonInteger $prepared.total_size) -or
                [long]$prepared.total_size -le 0) {
            throw 'MCACE_MATRIX_PUBLISH_PREPARED_TREE_INVALID'
        }
        $key = "$($prepared.project)|$($prepared.version)"
        if ($preparedMap.ContainsKey($key)) {
            throw "MCACE_MATRIX_PUBLISH_PREPARED_TREE_DUPLICATE|$key"
        }
        if (-not $assetMap.ContainsKey($key)) {
            throw "MCACE_MATRIX_PUBLISH_PREPARED_TREE_ASSET_MISSING|$key"
        }
        $asset = $assetMap[$key]
        if (-not (Test-StringEqual $prepared.build ([string]$asset.build)) -or
                -not (Test-StringEqual $prepared.server_sha256 ([string]$asset.sha256))) {
            throw "MCACE_MATRIX_PUBLISH_PREPARED_TREE_ASSET_MISMATCH|$key"
        }
        $preparedMap.Add($key, $prepared)
    }
    foreach ($key in @(
            'paper|1.21.11','paper|26.1.2','paper|26.2',
            'folia|1.21.11','folia|26.1.2','folia|26.2')) {
        if (-not $preparedMap.ContainsKey($key)) {
            throw "MCACE_MATRIX_PUBLISH_PREPARED_TREE_MISSING|$key"
        }
    }

    $jdkNames = @(
        'feature','version','java_executable_sha256','java_executable_size',
        'release_sha256','modules_sha256','modules_size','jvm_sha256','jvm_size')
    $jdkMap = [Collections.Generic.Dictionary[int,object]]::new()
    foreach ($jdk in @($Current.server_jdks)) {
        if (-not (Test-ExactProperties $jdk $jdkNames) -or
                -not (Test-JsonInteger $jdk.feature) -or
                [int]$jdk.feature -notin @(21,25) -or
                -not (Test-NonEmptyJsonString $jdk.version)) {
            throw 'MCACE_MATRIX_PUBLISH_JDK_INVALID'
        }
        foreach ($hashName in @(
                'java_executable_sha256','release_sha256','modules_sha256','jvm_sha256')) {
            if (-not (Test-Sha256 $jdk.$hashName)) {
                throw "MCACE_MATRIX_PUBLISH_JDK_HASH_INVALID|$hashName"
            }
        }
        foreach ($sizeName in @('java_executable_size','modules_size','jvm_size')) {
            if (-not (Test-JsonInteger $jdk.$sizeName) -or [long]$jdk.$sizeName -le 0) {
                throw "MCACE_MATRIX_PUBLISH_JDK_SIZE_INVALID|$sizeName"
            }
        }
        if ($jdkMap.ContainsKey([int]$jdk.feature)) {
            throw "MCACE_MATRIX_PUBLISH_JDK_DUPLICATE|$($jdk.feature)"
        }
        $jdkMap.Add([int]$jdk.feature, $jdk)
    }
    if (-not $jdkMap.ContainsKey(21) -or -not $jdkMap.ContainsKey(25) -or
            -not (Test-ExactProperties $Current.root_jdk $jdkNames)) {
        throw 'MCACE_MATRIX_PUBLISH_JDK_SET_INVALID'
    }
    foreach ($name in $jdkNames) {
        if ([string]$Current.root_jdk.$name -cne [string]$jdkMap[21].$name) {
            throw "MCACE_MATRIX_PUBLISH_ROOT_JDK_MISMATCH|$name"
        }
    }

    $gradleNames = @(
        'version','command_sha256','launcher_sha256','core_sha256',
        'installation_manifest_sha256','installation_file_count','installation_total_size')
    if (-not (Test-ExactProperties $Current.gradle $gradleNames) -or
            -not (Test-StringEqual $Current.gradle.version '9.6.1') -or
            -not (Test-JsonInteger $Current.gradle.installation_file_count) -or
            [int]$Current.gradle.installation_file_count -le 0 -or
            -not (Test-JsonInteger $Current.gradle.installation_total_size) -or
            [long]$Current.gradle.installation_total_size -le 0) {
        throw 'MCACE_MATRIX_PUBLISH_GRADLE_INVALID'
    }
    foreach ($hashName in @(
            'command_sha256','launcher_sha256','core_sha256','installation_manifest_sha256')) {
        if (-not (Test-Sha256 $Current.gradle.$hashName)) {
            throw "MCACE_MATRIX_PUBLISH_GRADLE_HASH_INVALID|$hashName"
        }
    }

    if (-not (Test-ExactProperties $Current.product_jars @('velocity','bungee','paper'))) {
        throw 'MCACE_MATRIX_PUBLISH_PRODUCT_SET_INVALID'
    }
    Assert-ProductDescriptor $Current.product_jars.velocity 'velocity' `
        'mcace-server-velocity/build/libs/mcace-server-velocity-0.0.1.jar'
    Assert-ProductDescriptor $Current.product_jars.bungee 'bungee' `
        'mcace-server-bungeecord/build/libs/mcace-server-bungeecord-0.0.1.jar'
    Assert-ProductDescriptor $Current.product_jars.paper 'paper' `
        'mcace-server-paper/build/libs/mcace-server-paper-0.0.1.jar'

    $expectedCases = @(Get-ExpectedCases)
    $definitions = @($Current.definitions)
    $definitionNames = @('case_id','minecraft_version','minecraft_protocol','server_java_feature',
        'backend','proxy','lane','selector','server_asset_identity','server_asset_sha256',
        'prepared_tree_sha256','proxy_asset_identity','proxy_asset_sha256')
    $definitionMap = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    for ($index = 0; $index -lt 12; $index++) {
        $actual = $definitions[$index]
        $expected = $expectedCases[$index]
        if (-not (Test-ExactProperties $actual $definitionNames) -or
                [string]$actual.case_id -cne [string]$expected.case_id -or
                [string]$actual.minecraft_version -cne [string]$expected.minecraft_version -or
                -not (Test-JsonInteger $actual.minecraft_protocol) -or
                [int]$actual.minecraft_protocol -ne [int]$expected.minecraft_protocol -or
                -not (Test-JsonInteger $actual.server_java_feature) -or
                [int]$actual.server_java_feature -ne [int]$expected.server_java_feature -or
                [string]$actual.backend -cne [string]$expected.backend -or
                [string]$actual.proxy -cne [string]$expected.proxy -or
                [string]$actual.lane -cne [string]$expected.lane -or
                [string]$actual.selector -cne [string]$expected.selector) {
            throw "MCACE_MATRIX_PUBLISH_DEFINITION_INVALID|$index"
        }
        $backendKey = "$(([string]$actual.backend).ToLowerInvariant())|$($actual.minecraft_version)"
        $proxyProject = if ([string]$actual.proxy -ceq 'VELOCITY') { 'velocity' } else { 'bungeecord' }
        $proxyVersion = if ($proxyProject -ceq 'velocity') { '3.5.1-615' } else { '2085' }
        if (-not $assetMap.ContainsKey($backendKey) -or
                -not $preparedMap.ContainsKey($backendKey) -or
                -not $assetMap.ContainsKey("$proxyProject|$proxyVersion")) {
            throw "MCACE_MATRIX_PUBLISH_DEFINITION_NATIVE_SOURCE_MISSING|$index"
        }
        $backendAsset = $assetMap[$backendKey]
        $proxyAsset = $assetMap["$proxyProject|$proxyVersion"]
        $prepared = $preparedMap[$backendKey]
        $backendIdentity = "$($backendAsset.project):$($backendAsset.version):$($backendAsset.build)"
        $proxyIdentity = "$($proxyAsset.project):$($proxyAsset.version):$($proxyAsset.build)"
        if (-not (Test-StringEqual $actual.server_asset_identity $backendIdentity) -or
                -not (Test-StringEqual $actual.server_asset_sha256 ([string]$backendAsset.sha256)) -or
                -not (Test-StringEqual $actual.prepared_tree_sha256 ([string]$prepared.prepared_tree_sha256)) -or
                -not (Test-StringEqual $actual.proxy_asset_identity $proxyIdentity) -or
                -not (Test-StringEqual $actual.proxy_asset_sha256 ([string]$proxyAsset.sha256))) {
            throw "MCACE_MATRIX_PUBLISH_DEFINITION_NATIVE_CROSS_BINDING_INVALID|$index"
        }
        $id = [string]$actual.case_id
        if ($definitionMap.ContainsKey($id)) {
            throw "MCACE_MATRIX_PUBLISH_DEFINITION_DUPLICATE|$id"
        }
        $definitionMap.Add($id, $actual)
    }

    $cases = @($Report.cases)
    if ($cases.Count -ne 12) {
        throw 'MCACE_MATRIX_PUBLISH_CURRENT_REPORT_CASE_SET_INVALID'
    }
    foreach ($case in $cases) {
        $id = [string]$case.case_id
        if (-not $definitionMap.ContainsKey($id)) {
            throw "MCACE_MATRIX_PUBLISH_CASE_DEFINITION_MISSING|$id"
        }
        $definition = $definitionMap[$id]
        foreach ($name in @(
                'minecraft_version','minecraft_protocol','server_java_feature','backend','proxy',
                'lane','selector','server_asset_identity','proxy_asset_identity')) {
            if ([string]$case.$name -cne [string]$definition.$name) {
                throw "MCACE_MATRIX_PUBLISH_CASE_DEFINITION_MISMATCH|$id|$name"
            }
        }
        $backendKey = "$(([string]$case.backend).ToLowerInvariant())|$($case.minecraft_version)"
        $proxyProject = if ([string]$case.proxy -ceq 'VELOCITY') { 'velocity' } else { 'bungeecord' }
        $proxyVersion = if ($proxyProject -ceq 'velocity') { '3.5.1-615' } else { '2085' }
        $backendAsset = $assetMap[$backendKey]
        $proxyAsset = $assetMap["$proxyProject|$proxyVersion"]
        $prepared = $preparedMap[$backendKey]
        $proxyProduct = if ($proxyProject -ceq 'velocity') {
            $Current.product_jars.velocity
        } else { $Current.product_jars.bungee }
        if (-not (Test-StringEqual $case.run_root.backend_jar_sha256 ([string]$backendAsset.sha256)) -or
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
            throw "MCACE_MATRIX_PUBLISH_CASE_NATIVE_CROSS_BINDING_INVALID|$id"
        }
    }
}

function Assert-RunRoot([object]$RunRoot, [object]$Expected, [object]$Products) {
    $names = @('proxy_jar_sha256','proxy_jar_size','backend_jar_sha256','backend_jar_size',
        'proxy_plugin_sha256','proxy_plugin_size','backend_plugin_sha256','backend_plugin_size',
        'prepared_tree_sha256','prepared_file_count','prepared_total_size')
    if (-not (Test-ExactProperties $RunRoot $names)) {
        throw "MCACE_MATRIX_PUBLISH_RUN_ROOT_INVALID|$($Expected.case_id)"
    }
    foreach ($hashName in @('proxy_jar_sha256','backend_jar_sha256','proxy_plugin_sha256',
            'backend_plugin_sha256','prepared_tree_sha256')) {
        if (-not (Test-Sha256 $RunRoot.$hashName)) {
            throw "MCACE_MATRIX_PUBLISH_RUN_ROOT_HASH_INVALID|$($Expected.case_id)|$hashName"
        }
    }
    foreach ($sizeName in @('proxy_jar_size','backend_jar_size','proxy_plugin_size',
            'backend_plugin_size','prepared_file_count','prepared_total_size')) {
        if (-not (Test-JsonInteger $RunRoot.$sizeName) -or [long]$RunRoot.$sizeName -le 0) {
            throw "MCACE_MATRIX_PUBLISH_RUN_ROOT_SIZE_INVALID|$($Expected.case_id)|$sizeName"
        }
    }
    $proxyProduct = if ([string]$Expected.proxy -ceq 'VELOCITY') {
        $Products.velocity
    } else { $Products.bungee }
    if ([string]$RunRoot.proxy_plugin_sha256 -cne [string]$proxyProduct.sha256 -or
            [long]$RunRoot.proxy_plugin_size -ne [long]$proxyProduct.size -or
            [string]$RunRoot.backend_plugin_sha256 -cne [string]$Products.paper.sha256 -or
            [long]$RunRoot.backend_plugin_size -ne [long]$Products.paper.size) {
        throw "MCACE_MATRIX_PUBLISH_CASE_PRODUCT_JAR_MISMATCH|$($Expected.case_id)"
    }
}

function Assert-Report([object]$Report, [object]$Products) {
    $names = @('schema','generated_at','source_mode','source_commit','release_source_commit',
        'artifact_source_commit','product_version',
        'target_versions','expected_case_count','observed_case_count','stable_case_count',
        'beta_case_count','all_cases_passed','cleanup_all_zero','raw_manifest_schema',
        'raw_manifest_sha256','raw_manifest_bytes','ordered_raw_report_set_sha256',
        'case_runtime_commitment_sha256','release_bundle_manifest_sha256',
        'release_bundle_artifact_set_sha256','matrix_product_jar_set_sha256',
        'supervisor_operation_attempt_id','supervisor_challenge_nonce',
        'supervisor_challenge_issued_at','supervisor_receipt_expires_at',
        'supervisor_trust_root_sha256','supervisor_signer_key_id',
        'supervisor_signature_algorithm',
        'independent_supervisor_signature_present','release_eligible','cases')
    if (-not (Test-ExactProperties $Report $names) -or
            [string]$Report.schema -cne $reportSchema -or
            [string]$Report.source_mode -cne 'EXECUTED' -or
            [string]$Report.source_commit -cne $ArtifactSourceCommit -or
            [string]$Report.artifact_source_commit -cne $ArtifactSourceCommit -or
            -not (Test-Commit $Report.release_source_commit) -or
            [string]$Report.product_version -cne $productVersion -or
            ((@($Report.target_versions) -join ',') -cne ($targetVersions -join ',')) -or
            -not (Test-JsonInteger $Report.expected_case_count) -or [int]$Report.expected_case_count -ne 12 -or
            -not (Test-JsonInteger $Report.observed_case_count) -or [int]$Report.observed_case_count -ne 12 -or
            -not (Test-JsonInteger $Report.stable_case_count) -or [int]$Report.stable_case_count -ne 10 -or
            -not (Test-JsonInteger $Report.beta_case_count) -or [int]$Report.beta_case_count -ne 2 -or
            -not (Test-True $Report.all_cases_passed) -or
            -not (Test-True $Report.cleanup_all_zero) -or
            [string]$Report.raw_manifest_schema -cne $rawManifestSchema -or
            -not (Test-Sha256 $Report.raw_manifest_sha256) -or
            -not (Test-JsonInteger $Report.raw_manifest_bytes) -or [long]$Report.raw_manifest_bytes -le 0 -or
            -not (Test-Sha256 $Report.ordered_raw_report_set_sha256) -or
            -not (Test-Sha256 $Report.case_runtime_commitment_sha256) -or
            -not (Test-Sha256 $Report.release_bundle_manifest_sha256) -or
            -not (Test-Sha256 $Report.release_bundle_artifact_set_sha256) -or
            -not (Test-Sha256 $Report.matrix_product_jar_set_sha256) -or
            [string]$Report.supervisor_operation_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$Report.supervisor_challenge_nonce -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-Sha256 $Report.supervisor_trust_root_sha256) -or
            [string]$Report.supervisor_signer_key_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$' -or
            [string]$Report.supervisor_signature_algorithm -cne 'RSA_PKCS1_SHA256' -or
            $Report.independent_supervisor_signature_present -isnot [bool] -or
            -not [bool]$Report.independent_supervisor_signature_present -or
            $Report.release_eligible -isnot [bool] -or -not [bool]$Report.release_eligible) {
        throw 'MCACE_MATRIX_PUBLISH_REPORT_INVALID'
    }
    $generated = ConvertTo-EvidenceTime $Report.generated_at 'report.generated_at'
    $cases = @($Report.cases)
    if ($cases.Count -ne 12) { throw 'MCACE_MATRIX_PUBLISH_COMPLETE_12_OF_12_REQUIRED' }
    $expectedCases = @(Get-ExpectedCases)
    $seenOrdinal = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $seenFolded = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $caseNames = @('case_id','raw_schema','minecraft_version','minecraft_protocol','server_java_feature',
        'backend','proxy','lane','selector','invocation_started_at','invocation_finished_at',
        'execution_mode','invocation_exit_code','invocation_log_sha256',
        'raw_report','raw_report_sha256','raw_report_size','raw_report_last_write_at',
        'server_asset_identity','proxy_asset_identity','run_root','cleanup_process_count',
        'remaining_run_process_count','sensitive_artifact_count','process_cleanup_observed','passed')
    for ($index = 0; $index -lt 12; $index++) {
        $case = $cases[$index]
        $expected = $expectedCases[$index]
        $caseId = [string]$case.case_id
        if (-not $seenOrdinal.Add($caseId) -or -not $seenFolded.Add($caseId)) {
            throw "MCACE_MATRIX_PUBLISH_DUPLICATE_OR_CASE_AMBIGUOUS_CASE|$caseId"
        }
        if (-not (Test-ExactProperties $case $caseNames) -or
                $caseId -cne [string]$expected.case_id -or
                -not (Test-JsonInteger $case.raw_schema) -or [int]$case.raw_schema -ne 4 -or
                [string]$case.minecraft_version -cne [string]$expected.minecraft_version -or
                [int]$case.minecraft_protocol -ne [int]$expected.minecraft_protocol -or
                [int]$case.server_java_feature -ne [int]$expected.server_java_feature -or
                [string]$case.backend -cne [string]$expected.backend -or
                [string]$case.proxy -cne [string]$expected.proxy -or
                [string]$case.lane -cne [string]$expected.lane -or
                [string]$case.selector -cne [string]$expected.selector -or
                [string]$case.execution_mode -cne 'EXECUTE' -or
                -not (Test-JsonInteger $case.invocation_exit_code) -or [int]$case.invocation_exit_code -ne 0 -or
                -not (Test-Sha256 $case.invocation_log_sha256) -or
                -not (Test-Sha256 $case.raw_report_sha256) -or
                -not (Test-JsonInteger $case.raw_report_size) -or [long]$case.raw_report_size -le 0 -or
                [string]::IsNullOrWhiteSpace([string]$case.server_asset_identity) -or
                [string]::IsNullOrWhiteSpace([string]$case.proxy_asset_identity) -or
                -not (Test-JsonInteger $case.cleanup_process_count) -or [int]$case.cleanup_process_count -lt 2 -or
                -not (Test-JsonInteger $case.remaining_run_process_count) -or [int]$case.remaining_run_process_count -ne 0 -or
                -not (Test-JsonInteger $case.sensitive_artifact_count) -or [int]$case.sensitive_artifact_count -ne 0 -or
                -not (Test-True $case.process_cleanup_observed) -or
                -not (Test-True $case.passed)) {
            throw "MCACE_MATRIX_PUBLISH_CASE_INVALID|$caseId"
        }
        Assert-CanonicalRelativePath $case.raw_report "case[$index].raw_report"
        $started = ConvertTo-EvidenceTime $case.invocation_started_at "case[$index].started"
        $finished = ConvertTo-EvidenceTime $case.invocation_finished_at "case[$index].finished"
        $written = ConvertTo-EvidenceTime $case.raw_report_last_write_at "case[$index].write"
        if ($finished -lt $started -or $written -lt $started.AddSeconds(-2) -or
                $written -gt $finished.AddSeconds(2) -or $generated -lt $finished) {
            throw "MCACE_MATRIX_PUBLISH_CASE_TIME_INVALID|$caseId"
        }
        Assert-RunRoot $case.run_root $expected $Products
    }
}

function Assert-Binding([object]$Binding, [object]$ReportDocument, [object]$Report) {
    $names = @('schema','generated_at','report_schema','report_generated_at','report_sha256',
        'report_bytes','source_mode','source_commit','release_source_commit',
        'artifact_source_commit','product_version','raw_manifest_schema',
        'raw_manifest_sha256','raw_manifest_bytes','ordered_raw_report_set_sha256',
        'case_runtime_commitment_sha256','release_bundle_manifest_sha256',
        'release_bundle_artifact_set_sha256','matrix_product_jar_set_sha256',
        'supervisor_operation_attempt_id','supervisor_challenge_nonce',
        'supervisor_challenge_issued_at','supervisor_receipt_expires_at',
        'supervisor_trust_root_sha256','supervisor_signer_key_id',
        'supervisor_signature_algorithm',
        'current_sha256','current','independent_supervisor_signature_present',
        'release_eligible','passed')
    if (-not (Test-ExactProperties $Binding $names) -or
            [string]$Binding.schema -cne $bindingSchema -or
            [string]$Binding.report_schema -cne $reportSchema -or
            -not (Test-Sha256 $Binding.report_sha256) -or
            [string]$Binding.report_sha256 -cne [string]$ReportDocument.sha256 -or
            -not (Test-JsonInteger $Binding.report_bytes) -or
            [long]$Binding.report_bytes -ne [long]$ReportDocument.size_bytes -or
            [string]$Binding.source_mode -cne 'EXECUTED' -or
            [string]$Binding.source_commit -cne $ArtifactSourceCommit -or
            [string]$Binding.source_commit -cne [string]$Report.source_commit -or
            [string]$Binding.artifact_source_commit -cne $ArtifactSourceCommit -or
            [string]$Binding.release_source_commit -cne [string]$Report.release_source_commit -or
            [string]$Binding.product_version -cne $productVersion -or
            [string]$Binding.product_version -cne [string]$Report.product_version -or
            [string]$Binding.raw_manifest_schema -cne $rawManifestSchema -or
            [string]$Binding.raw_manifest_sha256 -cne [string]$Report.raw_manifest_sha256 -or
            [long]$Binding.raw_manifest_bytes -ne [long]$Report.raw_manifest_bytes -or
            [string]$Binding.ordered_raw_report_set_sha256 -cne [string]$Report.ordered_raw_report_set_sha256 -or
            [string]$Binding.case_runtime_commitment_sha256 -cne [string]$Report.case_runtime_commitment_sha256 -or
            [string]$Binding.release_bundle_manifest_sha256 -cne [string]$Report.release_bundle_manifest_sha256 -or
            [string]$Binding.release_bundle_artifact_set_sha256 -cne [string]$Report.release_bundle_artifact_set_sha256 -or
            [string]$Binding.matrix_product_jar_set_sha256 -cne [string]$Report.matrix_product_jar_set_sha256 -or
            [string]$Binding.supervisor_operation_attempt_id -cne [string]$Report.supervisor_operation_attempt_id -or
            [string]$Binding.supervisor_challenge_nonce -cne [string]$Report.supervisor_challenge_nonce -or
            [string]$Binding.supervisor_challenge_issued_at -cne [string]$Report.supervisor_challenge_issued_at -or
            [string]$Binding.supervisor_receipt_expires_at -cne [string]$Report.supervisor_receipt_expires_at -or
            [string]$Binding.supervisor_trust_root_sha256 -cne [string]$Report.supervisor_trust_root_sha256 -or
            [string]$Binding.supervisor_signer_key_id -cne [string]$Report.supervisor_signer_key_id -or
            [string]$Binding.supervisor_signature_algorithm -cne 'RSA_PKCS1_SHA256' -or
            -not (Test-Sha256 $Binding.current_sha256) -or
            $Binding.independent_supervisor_signature_present -isnot [bool] -or
            -not [bool]$Binding.independent_supervisor_signature_present -or
            $Binding.release_eligible -isnot [bool] -or -not [bool]$Binding.release_eligible -or
            -not (Test-True $Binding.passed)) {
        throw 'MCACE_MATRIX_PUBLISH_BINDING_INVALID'
    }
    Assert-SameTime $Binding.generated_at $Report.generated_at 'binding.generated_at'
    Assert-SameTime $Binding.report_generated_at $Report.generated_at 'binding.report_generated_at'
    Assert-CurrentBinding $Binding.current $Report
    $currentHash = Get-BytesSha256 (ConvertTo-CompactJsonBytes $Binding.current)
    if ([string]$Binding.current_sha256 -cne $currentHash) {
        throw 'MCACE_MATRIX_PUBLISH_CURRENT_HASH_INVALID'
    }
}

function Assert-CommitDocument(
        [object]$Commit,
        [object]$ReportDocument,
        [object]$BindingDocument,
        [object]$Report) {
    $names = @('schema','generated_at','report_schema','binding_schema','report_sha256',
        'report_bytes','binding_sha256','binding_bytes','raw_manifest_schema',
        'raw_manifest_sha256','raw_manifest_bytes','ordered_raw_report_set_sha256',
        'source_commit','release_source_commit','artifact_source_commit','product_version',
        'supervisor_signing_request_schema','supervisor_signing_request_sha256',
        'supervisor_signing_request_bytes','supervisor_receipt_schema',
        'supervisor_receipt_sha256','supervisor_receipt_bytes','supervisor_operation_attempt_id',
        'supervisor_challenge_nonce','supervisor_trust_root_sha256',
        'independent_supervisor_signature_present',
        'release_eligible','committed')
    if (-not (Test-ExactProperties $Commit $names) -or
            [string]$Commit.schema -cne $commitSchema -or
            [string]$Commit.report_schema -cne $reportSchema -or
            [string]$Commit.binding_schema -cne $bindingSchema -or
            -not (Test-Sha256 $Commit.report_sha256) -or
            [string]$Commit.report_sha256 -cne [string]$ReportDocument.sha256 -or
            -not (Test-JsonInteger $Commit.report_bytes) -or
            [long]$Commit.report_bytes -ne [long]$ReportDocument.size_bytes -or
            -not (Test-Sha256 $Commit.binding_sha256) -or
            [string]$Commit.binding_sha256 -cne [string]$BindingDocument.sha256 -or
            -not (Test-JsonInteger $Commit.binding_bytes) -or
            [long]$Commit.binding_bytes -ne [long]$BindingDocument.size_bytes -or
            [string]$Commit.raw_manifest_schema -cne $rawManifestSchema -or
            [string]$Commit.raw_manifest_sha256 -cne [string]$Report.raw_manifest_sha256 -or
            [long]$Commit.raw_manifest_bytes -ne [long]$Report.raw_manifest_bytes -or
            [string]$Commit.ordered_raw_report_set_sha256 -cne [string]$Report.ordered_raw_report_set_sha256 -or
            [string]$Commit.source_commit -cne $ArtifactSourceCommit -or
            [string]$Commit.artifact_source_commit -cne $ArtifactSourceCommit -or
            [string]$Commit.release_source_commit -cne [string]$Report.release_source_commit -or
            [string]$Commit.product_version -cne $productVersion -or
            [string]$Commit.supervisor_signing_request_schema -cne $signingRequestSchema -or
            -not (Test-Sha256 $Commit.supervisor_signing_request_sha256) -or
            -not (Test-JsonInteger $Commit.supervisor_signing_request_bytes) -or
            [long]$Commit.supervisor_signing_request_bytes -le 0 -or
            [string]$Commit.supervisor_receipt_schema -cne $receiptSchema -or
            -not (Test-Sha256 $Commit.supervisor_receipt_sha256) -or
            -not (Test-JsonInteger $Commit.supervisor_receipt_bytes) -or
            [long]$Commit.supervisor_receipt_bytes -le 0 -or
            [string]$Commit.supervisor_operation_attempt_id -cne [string]$Report.supervisor_operation_attempt_id -or
            [string]$Commit.supervisor_challenge_nonce -cne [string]$Report.supervisor_challenge_nonce -or
            [string]$Commit.supervisor_trust_root_sha256 -cne [string]$Report.supervisor_trust_root_sha256 -or
            $Commit.independent_supervisor_signature_present -isnot [bool] -or
            -not [bool]$Commit.independent_supervisor_signature_present -or
            $Commit.release_eligible -isnot [bool] -or -not [bool]$Commit.release_eligible -or
            -not (Test-True $Commit.committed)) {
        throw 'MCACE_MATRIX_PUBLISH_COMMIT_INVALID'
    }
    Assert-SameTime $Commit.generated_at $Report.generated_at 'commit.generated_at'
}

function Assert-ExactTripletPaths {
    $reportFull = [IO.Path]::GetFullPath($ReportPath)
    $bindingFull = [IO.Path]::GetFullPath($BindingPath)
    $commitFull = [IO.Path]::GetFullPath($CommitPath)
    foreach ($entry in @(
            [pscustomobject]@{ path=$reportFull; name='report.json'; role='report' },
            [pscustomobject]@{ path=$bindingFull; name='binding.json'; role='binding' },
            [pscustomobject]@{ path=$commitFull; name='commit.json'; role='commit' })) {
        $null = Assert-PathChainNoReparse $entry.path $true $entry.role
        if ((Split-Path -Leaf $entry.path) -cne $entry.name) {
            throw "MCACE_MATRIX_PUBLISH_INPUT_NAME_INVALID|$($entry.role)"
        }
    }
    $directories = @(
        (Split-Path -Parent $reportFull),
        (Split-Path -Parent $bindingFull),
        (Split-Path -Parent $commitFull))
    $comparison = if (Test-IsWindowsPlatform) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    if (-not $directories[0].Equals($directories[1], $comparison) -or
            -not $directories[0].Equals($directories[2], $comparison)) {
        throw 'MCACE_MATRIX_PUBLISH_TRIPLET_COMMON_DIRECTORY_REQUIRED'
    }
    $entries = @(Get-ChildItem -LiteralPath $directories[0] -Force -ErrorAction Stop)
    $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in @('report.json','binding.json','commit.json','raw-manifest.json',
            'supervisor-signing-request.json','supervisor-receipt.json','raw')) {
        [void]$expected.Add($name)
    }
    if ($entries.Count -ne 7) { throw 'MCACE_MATRIX_PUBLISH_EXACT_PACKAGE_REQUIRED' }
    foreach ($entry in $entries) {
        $rawDirectory = [string]$entry.Name -ceq 'raw'
        if (($rawDirectory -and -not $entry.PSIsContainer) -or
                (-not $rawDirectory -and $entry.PSIsContainer) -or
                ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not $expected.Remove([string]$entry.Name)) {
            throw "MCACE_MATRIX_PUBLISH_PACKAGE_ENTRY_INVALID|$($entry.Name)"
        }
    }
    if ($expected.Count -ne 0) { throw 'MCACE_MATRIX_PUBLISH_EXACT_PACKAGE_REQUIRED' }
    return [pscustomobject]@{
        directory=$directories[0]; report=$reportFull; binding=$bindingFull; commit=$commitFull
        raw_manifest=(Join-Path $directories[0] 'raw-manifest.json')
        signing_request=(Join-Path $directories[0] 'supervisor-signing-request.json')
        supervisor_receipt=(Join-Path $directories[0] 'supervisor-receipt.json')
        raw=(Join-Path $directories[0] 'raw')
    }
}

function Assert-ServerJarBytes([byte[]]$Bytes, [string]$FileName) {
    $required = [ordered]@{
        'mcace-server-velocity.jar'='com/ellan/mcace/velocity/MCAceVelocityPlugin.class'
        'mcace-server-bungeecord.jar'='com/ellan/mcace/bungeecord/MCAceBungeePlugin.class'
        'mcace-server-paper.jar'='com/ellan/mcace/paper/MCAcePaperPlugin.class'
    }
    if (-not $required.Contains($FileName)) { return }
    if ($Bytes.Length -lt 128 -or $Bytes[0] -ne 0x50 -or $Bytes[1] -ne 0x4b) {
        throw "MCACE_MATRIX_PUBLISH_SERVER_JAR_INVALID|$FileName"
    }
    try {
        $memory = [IO.MemoryStream]::new($Bytes,$false)
        try {
            $archive = [IO.Compression.ZipArchive]::new(
                $memory,[IO.Compression.ZipArchiveMode]::Read,$false)
            try {
                $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                foreach ($entry in $archive.Entries) {
                    $name = [string]$entry.FullName
                    if ([string]::IsNullOrWhiteSpace($name) -or $name.IndexOf('\') -ge 0 -or
                            $name -match '(^|/)\.\.?(?:/|$)' -or -not $seen.Add($name)) {
                        throw "MCACE_MATRIX_PUBLISH_SERVER_JAR_ENTRY_INVALID|$FileName"
                    }
                }
                if (-not $seen.Contains([string]$required[$FileName])) {
                    throw "MCACE_MATRIX_PUBLISH_SERVER_JAR_MARKER_MISSING|$FileName"
                }
            } finally { $archive.Dispose() }
        } finally { $memory.Dispose() }
    } catch {
        if ($_.Exception.Message -like 'MCACE_MATRIX_PUBLISH_SERVER_JAR*') { throw }
        throw "MCACE_MATRIX_PUBLISH_SERVER_JAR_INVALID|$FileName"
    }
}

function Read-ReleaseBundle([string]$Root) {
    $rootFull = Assert-PathChainNoReparse ([IO.Path]::GetFullPath($Root)) $true 'release-bundle-root'
    if (-not (Test-Path -LiteralPath $rootFull -PathType Container)) {
        throw 'MCACE_MATRIX_PUBLISH_RELEASE_BUNDLE_DIRECTORY_REQUIRED'
    }
    $jarNames = @('mcace-client-fabric-1.21.11.jar','mcace-client-fabric-26.1.2.jar',
        'mcace-client-fabric-26.2.jar','mcace-server-velocity.jar',
        'mcace-server-bungeecord.jar','mcace-server-paper.jar')
    $expectedNames = @('SHA256SUMS','release-manifest.properties') + $jarNames
    $entries = @(Get-ChildItem -LiteralPath $rootFull -Force -ErrorAction Stop)
    if ($entries.Count -ne 8 -or
            ((@($entries.Name | Sort-Object) -join '|') -cne (($expectedNames | Sort-Object) -join '|'))) {
        throw 'MCACE_MATRIX_PUBLISH_RELEASE_BUNDLE_FILE_SET_INVALID'
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'MCACE_MATRIX_PUBLISH_RELEASE_BUNDLE_ENTRY_TYPE_INVALID'
        }
    }
    $manifestDocument = Read-LockedFileBytes (Join-Path $rootFull 'release-manifest.properties') `
        1 $maximumBundleTextBytes 'release-manifest'
    $sumsDocument = Read-LockedFileBytes (Join-Path $rootFull 'SHA256SUMS') `
        1 $maximumBundleTextBytes 'release-sha256sums'
    foreach ($document in @($manifestDocument,$sumsDocument)) {
        if ($document.bytes.Length -ge 3 -and $document.bytes[0] -eq 0xef -and
                $document.bytes[1] -eq 0xbb -and $document.bytes[2] -eq 0xbf) {
            throw 'MCACE_MATRIX_PUBLISH_RELEASE_BUNDLE_BOM_REJECTED'
        }
    }
    try {
        $manifestRaw = $utf8Strict.GetString($manifestDocument.bytes)
        $sumsRaw = $utf8Strict.GetString($sumsDocument.bytes)
    } catch { throw 'MCACE_MATRIX_PUBLISH_RELEASE_BUNDLE_UTF8_INVALID' }
    if ($manifestRaw.Contains("`r") -or -not $manifestRaw.EndsWith("`n") -or
            $sumsRaw.Contains("`r") -or -not $sumsRaw.EndsWith("`n")) {
        throw 'MCACE_MATRIX_PUBLISH_RELEASE_BUNDLE_CANONICAL_ENCODING_INVALID'
    }
    $manifest = [ordered]@{}
    $manifestKeys = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($line in @($manifestRaw.TrimEnd("`n") -split "`n")) {
        if ($line.Length -eq 0 -or $line -cne $line.Trim()) {
            throw 'MCACE_MATRIX_PUBLISH_RELEASE_MANIFEST_LINE_INVALID'
        }
        $separator = $line.IndexOf('=')
        if ($separator -lt 1) { throw 'MCACE_MATRIX_PUBLISH_RELEASE_MANIFEST_LINE_INVALID' }
        $key = $line.Substring(0,$separator)
        $value = $line.Substring($separator + 1)
        if ($key -cnotmatch '^[A-Za-z0-9._-]+$' -or -not $manifestKeys.Add($key)) {
            throw 'MCACE_MATRIX_PUBLISH_RELEASE_MANIFEST_KEY_INVALID'
        }
        $manifest[$key] = $value
    }
    $requiredKeys = @('schema','bundle_profile','release_identity','deployable_count',
        'bundle_entry_count','product_version','source_commit','artifact_source_commit',
        'root_java_version','root_java_specification_version','root_gradle_version',
        'modern_java_version','modern_java_specification_version','modern_gradle_version')
    foreach ($jarName in $jarNames) {
        $key = $jarName.Remove($jarName.Length - 4).Replace('-', '_').Replace('.', '_')
        $requiredKeys += "artifact.$key.file"
        $requiredKeys += "artifact.$key.sha256"
        if ($jarName.StartsWith('mcace-client-fabric-', [StringComparison]::Ordinal)) {
            $requiredKeys += "artifact.$key.minecraft_version"
            $requiredKeys += "artifact.$key.client_build_id"
        }
    }
    if ($manifest.Count -ne $requiredKeys.Count -or
            (($manifest.Keys | Sort-Object) -join '|') -cne (($requiredKeys | Sort-Object) -join '|') -or
            [string]$manifest.schema -cne $bundleSchema -or
            [string]$manifest.bundle_profile -cne 'RELEASE' -or
            [string]$manifest.release_identity -cne 'true' -or
            [string]$manifest.deployable_count -cne '6' -or
            [string]$manifest.bundle_entry_count -cne '8' -or
            [string]$manifest.product_version -cne $productVersion -or
            -not (Test-Commit $manifest.source_commit) -or
            [string]$manifest.artifact_source_commit -cne $ArtifactSourceCommit) {
        throw 'MCACE_MATRIX_PUBLISH_RELEASE_MANIFEST_INVALID'
    }
    $sumLines = @($sumsRaw.TrimEnd("`n") -split "`n")
    if ($sumLines.Count -ne 6) { throw 'MCACE_MATRIX_PUBLISH_RELEASE_SHA256SUMS_INVALID' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $artifactsByName = [ordered]@{}
    foreach ($line in $sumLines) {
        if ($line -cnotmatch '^(?<sha>[0-9a-f]{64})  (?<file>[A-Za-z0-9][A-Za-z0-9._-]*\.jar)$' -or
                $Matches.file -cnotin $jarNames -or -not $seen.Add($Matches.file)) {
            throw 'MCACE_MATRIX_PUBLISH_RELEASE_SHA256SUMS_INVALID'
        }
        $fileName = [string]$Matches.file
        $fileSha256 = [string]$Matches.sha
        $artifact = Read-LockedFileBytes (Join-Path $rootFull $fileName) `
            1 $maximumBundleArtifactBytes "release-artifact-$fileName"
        $key = $fileName.Remove($fileName.Length - 4).Replace('-', '_').Replace('.', '_')
        if ([string]$artifact.sha256 -cne $fileSha256 -or
                [string]$manifest["artifact.$key.file"] -cne $fileName -or
                [string]$manifest["artifact.$key.sha256"] -cne $fileSha256) {
            throw "MCACE_MATRIX_PUBLISH_RELEASE_ARTIFACT_BINDING_INVALID|$fileName"
        }
        Assert-ServerJarBytes ([byte[]]$artifact.bytes) $fileName
        if ($fileName -cmatch '^mcace-client-fabric-(?<target>1\.21\.11|26\.1\.2|26\.2)\.jar$') {
            $fabricTarget = [string]$Matches.target
            if ([string]$manifest["artifact.$key.minecraft_version"] -cne $fabricTarget -or
                    [string]$manifest["artifact.$key.client_build_id"] -cne
                        "fabric-$fabricTarget-$ArtifactSourceCommit") {
                throw "MCACE_MATRIX_PUBLISH_RELEASE_CLIENT_IDENTITY_INVALID|$fileName"
            }
        }
        $artifactsByName[$fileName] = [pscustomobject][ordered]@{
            file = $fileName
            sha256 = [string]$artifact.sha256
            size_bytes = [long]$artifact.size_bytes
        }
    }
    if ($seen.Count -ne 6) { throw 'MCACE_MATRIX_PUBLISH_RELEASE_SHA256SUMS_INVALID' }
    return [pscustomobject]@{
        schema = $bundleSchema
        source_commit = [string]$manifest.source_commit
        artifact_source_commit = [string]$manifest.artifact_source_commit
        product_version = [string]$manifest.product_version
        manifest_sha256 = [string]$manifestDocument.sha256
        manifest_size_bytes = [long]$manifestDocument.size_bytes
        sha256sums_sha256 = [string]$sumsDocument.sha256
        sha256sums_size_bytes = [long]$sumsDocument.size_bytes
        artifacts = [pscustomobject]$artifactsByName
        artifact_list = @($jarNames | Sort-Object | ForEach-Object { $artifactsByName[$_] })
    }
}

function Assert-CrossBinding([object]$Products, [object]$Bundle) {
    $map = [ordered]@{
        velocity = 'mcace-server-velocity.jar'
        bungee = 'mcace-server-bungeecord.jar'
        paper = 'mcace-server-paper.jar'
    }
    $bindings = New-Object 'Collections.Generic.List[object]'
    foreach ($pair in $map.GetEnumerator()) {
        $matrix = $Products.([string]$pair.Key)
        $release = $Bundle.artifacts.([string]$pair.Value)
        if ($null -eq $release -or [string]$matrix.sha256 -cne [string]$release.sha256 -or
                [long]$matrix.size -ne [long]$release.size_bytes) {
            throw "MCACE_MATRIX_PUBLISH_RELEASE_PRODUCT_CROSS_BINDING_INVALID|$($pair.Key)"
        }
        [void]$bindings.Add([pscustomobject][ordered]@{
            role = [string]$pair.Key
            bundle_file = [string]$pair.Value
            matrix_relative = [string]$matrix.relative
            sha256 = [string]$matrix.sha256
            size_bytes = [long]$matrix.size
        })
    }
    return $bindings.ToArray()
}

function Get-CaseRuntimeCommitments([object]$Report, [object]$RawEvidence) {
    $commitments = [Collections.Generic.List[object]]::new()
    $processCount = 0
    for ($caseIndex = 0; $caseIndex -lt 12; $caseIndex++) {
        $case = @($Report.cases)[$caseIndex]
        $raw = @($RawEvidence.documents)[$caseIndex].value
        $processes = [Collections.Generic.List[object]]::new()
        $cleanupIds = @($raw.cleanup_process_ids)
        for ($processIndex = 0; $processIndex -lt $cleanupIds.Count; $processIndex++) {
            $role = if ($processIndex -eq 0) { 'PROXY' } elseif ($processIndex -eq 1) {
                'BACKEND'
            } else { "AUXILIARY_$($processIndex - 1)" }
            $identityBody = [pscustomobject][ordered]@{
                case_id = [string]$case.case_id
                role = $role
                process_id = [long]$cleanupIds[$processIndex]
                invocation_started_at = [string]$case.invocation_started_at
                invocation_finished_at = [string]$case.invocation_finished_at
                proxy_jar_sha256 = [string]$case.run_root.proxy_jar_sha256
                backend_jar_sha256 = [string]$case.run_root.backend_jar_sha256
            }
            [void]$processes.Add([pscustomobject][ordered]@{
                role = $role
                process_id = [long]$cleanupIds[$processIndex]
                process_incarnation_sha256 = Get-SetSha256 `
                    'MCACE_SERVER_VERSION_PROCESS_MATRIX_PROCESS_INCARNATION_V1' $identityBody
                cleanup_observed = $true
                remaining_process_count = 0
            })
            $processCount++
        }
        [void]$commitments.Add([pscustomobject][ordered]@{
            ordinal = $caseIndex + 1
            case_id = [string]$case.case_id
            invocation_started_at = [string]$case.invocation_started_at
            invocation_finished_at = [string]$case.invocation_finished_at
            invocation_log_sha256 = [string]$case.invocation_log_sha256
            raw_report_sha256 = [string]$case.raw_report_sha256
            raw_report_size_bytes = [long]$case.raw_report_size
            cleanup_process_count = [int]$case.cleanup_process_count
            remaining_process_count = 0
            process_cleanup_observed = $true
            processes = $processes.ToArray()
        })
    }
    return [pscustomobject]@{
        values=$commitments.ToArray()
        count=12
        process_count=$processCount
        sha256=Get-SetSha256 $caseRuntimeDomain $commitments.ToArray()
    }
}

function Get-ReleaseArtifactCommitment([object]$Bundle) {
    $values = @($Bundle.artifact_list | Sort-Object file | ForEach-Object {
        [pscustomobject][ordered]@{
            file=[string]$_.file; sha256=[string]$_.sha256; size_bytes=[long]$_.size_bytes
        }
    })
    return [pscustomobject]@{
        values=$values; count=$values.Count
        sha256=Get-SetSha256 $releaseArtifactDomain $values
    }
}

function Get-MatrixProductCommitment([object[]]$Bindings) {
    $values = @($Bindings | ForEach-Object {
        [pscustomobject][ordered]@{
            role=[string]$_.role; bundle_file=[string]$_.bundle_file
            matrix_relative=[string]$_.matrix_relative; sha256=[string]$_.sha256
            size_bytes=[long]$_.size_bytes
        }
    })
    return [pscustomobject]@{
        values=$values; count=$values.Count
        sha256=Get-SetSha256 $matrixProductDomain $values
    }
}

function Assert-SupervisorSigningRequest(
        [object]$Document,
        [object]$ReportDocument,
        [object]$BindingDocument,
        [object]$RawManifestDocument,
        [object]$Report,
        [object]$Bundle,
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
            [string]$request.schema -cne $signingRequestSchema -or
            [string]$request.source_mode -cne 'EXECUTED_AWAITING_EXTERNAL_SUPERVISOR' -or
            [string]$request.release_source_commit -cne [string]$Bundle.source_commit -or
            [string]$request.artifact_source_commit -cne $ArtifactSourceCommit -or
            [string]$request.product_version -cne $productVersion -or
            [string]$request.operation_attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$request.challenge_nonce -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$request.report_sha256 -cne [string]$ReportDocument.sha256 -or
            [long]$request.report_size_bytes -ne [long]$ReportDocument.size_bytes -or
            [string]$request.binding_sha256 -cne [string]$BindingDocument.sha256 -or
            [long]$request.binding_size_bytes -ne [long]$BindingDocument.size_bytes -or
            [string]$request.raw_manifest_sha256 -cne [string]$RawManifestDocument.sha256 -or
            [long]$request.raw_manifest_size_bytes -ne [long]$RawManifestDocument.size_bytes -or
            [string]$request.ordered_raw_report_set_sha256 -cne
                [string]$Report.ordered_raw_report_set_sha256 -or
            [string]$request.case_runtime_commitment_sha256 -cne [string]$CaseCommitment.sha256 -or
            [int]$request.case_count -ne 12 -or
            [int]$request.process_identity_count -ne [int]$CaseCommitment.process_count -or
            [string]$request.release_bundle_schema -cne $bundleSchema -or
            [string]$request.release_bundle_manifest_sha256 -cne [string]$Bundle.manifest_sha256 -or
            [long]$request.release_bundle_manifest_size_bytes -ne [long]$Bundle.manifest_size_bytes -or
            [string]$request.release_bundle_sha256s_sha256 -cne [string]$Bundle.sha256sums_sha256 -or
            [long]$request.release_bundle_sha256s_size_bytes -ne [long]$Bundle.sha256sums_size_bytes -or
            [string]$request.release_bundle_artifact_set_sha256 -cne [string]$ReleaseCommitment.sha256 -or
            [int]$request.release_bundle_artifact_count -ne 6 -or
            [string]$request.matrix_product_jar_set_sha256 -cne [string]$ProductCommitment.sha256 -or
            [int]$request.matrix_product_jar_count -ne 3 -or
            [string]$request.supervisor_trust_root_sha256 -cne [string]$TrustRoot.document.sha256 -or
            [string]$request.supervisor_signer_key_id -cne [string]$TrustRoot.value.key_id -or
            [string]$request.signature_algorithm -cne 'RSA_PKCS1_SHA256') {
        throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_SIGNING_REQUEST_INVALID'
    }
    foreach ($pair in @(
            [pscustomobject]@{ actual=$request.case_runtime_commitments; expected=$CaseCommitment.values; domain=$caseRuntimeDomain },
            [pscustomobject]@{ actual=$request.release_bundle_artifacts; expected=$ReleaseCommitment.values; domain=$releaseArtifactDomain },
            [pscustomobject]@{ actual=$request.matrix_product_jars; expected=$ProductCommitment.values; domain=$matrixProductDomain })) {
        if (-not (Test-JsonArray $pair.actual) -or
                (Get-SetSha256 ([string]$pair.domain) @($pair.actual)) -cne
                    (Get-SetSha256 ([string]$pair.domain) @($pair.expected))) {
            throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_SIGNING_REQUEST_SET_INVALID'
        }
    }
    $generated = ConvertTo-EvidenceTime $request.generated_at 'signing-request.generated_at'
    $issued = ConvertTo-EvidenceTime $request.challenge_issued_at 'signing-request.challenge_issued_at'
    $expires = ConvertTo-EvidenceTime $request.receipt_not_after 'signing-request.receipt_not_after'
    if ($generated.Ticks -ne $issued.Ticks -or $issued -lt
            (ConvertTo-EvidenceTime $Report.generated_at 'report.generated_at') -or
            $expires -le $issued -or ($expires - $issued).TotalMinutes -gt 30) {
        throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_SIGNING_REQUEST_TIME_INVALID'
    }
    return [pscustomobject]@{ value=$request; issued_at=$issued; expires_at=$expires }
}

function Assert-SupervisorReceipt(
        [object]$Document,
        [object]$RequestValidation,
        [object]$TrustRoot) {
    $receipt = $Document.value
    if (-not (Test-ExactProperties $receipt $matrixReceiptPropertyNames)) {
        throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_SCHEMA_INVALID'
    }
    foreach ($name in @('report_size_bytes','binding_size_bytes','raw_manifest_size_bytes',
            'case_count','process_identity_count','release_bundle_manifest_size_bytes',
            'release_bundle_sha256s_size_bytes','release_bundle_artifact_count',
            'matrix_product_jar_count')) {
        if (-not (Test-JsonInteger $receipt.$name)) {
            throw "MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_INTEGER_INVALID|$name"
        }
    }
    foreach ($name in @('supervisor_independent','test_fixture')) {
        if ($receipt.$name -isnot [bool]) {
            throw "MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_BOOLEAN_INVALID|$name"
        }
    }
    if ([string]$receipt.schema -cne $receiptSchema -or
            [string]$receipt.artifact_class -cne 'EXTERNALLY_SIGNED_MATRIX_SUPERVISOR_RECEIPT' -or
            [string]$receipt.source_mode -cne 'EXTERNAL_MATRIX_SUPERVISOR' -or
            -not [bool]$receipt.supervisor_independent -or [bool]$receipt.test_fixture -or
            [string]$receipt.signer_key_id -cne [string]$TrustRoot.value.key_id -or
            [string]$receipt.signer_trust_root_sha256 -cne [string]$TrustRoot.document.sha256 -or
            [string]$receipt.signature_algorithm -cne 'RSA_PKCS1_SHA256') {
        throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_PROVENANCE_INVALID'
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
        if ((Test-JsonInteger $expected)) {
            if (-not (Test-JsonInteger $actual) -or [long]$actual -ne [long]$expected) {
                throw "MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_BINDING_INVALID|$($pair.Key)"
            }
        } elseif ([string]$actual -cne [string]$expected) {
            throw "MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_BINDING_INVALID|$($pair.Key)"
        }
    }
    $signedAt = ConvertTo-EvidenceTime $receipt.signed_at 'supervisor-receipt.signed_at'
    $expiresAt = ConvertTo-EvidenceTime $receipt.expires_at 'supervisor-receipt.expires_at'
    if ($expiresAt.Ticks -ne $RequestValidation.expires_at.Ticks -or
            $signedAt -lt $RequestValidation.issued_at -or $signedAt -gt $expiresAt -or
            [DateTimeOffset]::UtcNow -gt $expiresAt.AddMinutes(1)) {
        throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_EXPIRED_OR_TIME_INVALID'
    }
    try { $signature = [Convert]::FromBase64String([string]$receipt.signature_base64) }
    catch { throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_SIGNATURE_ENCODING_INVALID' }
    if ($signature.Length -ne $TrustRoot.modulus.Length -or
            -not (Test-RsaPkcs1Sha256Signature `
                (Get-MatrixReceiptSigningPayload $receipt) $signature `
                $TrustRoot.modulus $TrustRoot.exponent)) {
        throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_SIGNATURE_INVALID'
    }
    # The detached receipt is signed and hashed as compact JSON without a
    # trailing newline.  Verify the exact bytes before copying them into the
    # published package; this keeps the publisher aligned with the producer's
    # cross-process commitment contract.
    if ([string]$Document.sha256 -cne
            (Get-BytesSha256 (ConvertTo-CommitmentJsonBytes $receipt))) {
        throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_NONCANONICAL'
    }
    return [pscustomobject]@{ value=$receipt; signed_at=$signedAt; expires_at=$expiresAt }
}

function Assert-NoPublishedSupervisorReplay([object]$Receipt, [string]$EvidenceId) {
    if (-not (Test-Path -LiteralPath $outputRootFull -PathType Container)) { return }
    foreach ($file in @(Get-ChildItem -LiteralPath $outputRootFull -File `
            -Filter 'server-version-process-matrix-*.json' -ErrorAction Stop)) {
        if ([string]$file.BaseName -ceq $EvidenceId) { continue }

        # The repository contains historical durable evidence documents whose
        # schemas predate the V4 publisher and whose byte-level canonical form
        # is intentionally different (some are compact JSON without a final
        # LF).  Identify the schema before applying the V4 strict parser so a
        # valid legacy document cannot block publication of a new V4 index.
        # Malformed JSON still fails closed; only a valid non-V4 schema is
        # ignored for replay purposes.
        $legacyRaw = [IO.File]::ReadAllText($file.FullName, $utf8Strict)
        try {
            $legacyValue = ConvertFrom-Json -InputObject $legacyRaw -ErrorAction Stop
        } catch {
            throw "MCACE_MATRIX_PUBLISH_REPLAY_INDEX_JSON_INVALID|$($file.Name)"
        }
        if ($null -eq $legacyValue -or
                [string]$legacyValue.schema -cne $indexSchema) {
            continue
        }
        $existing = Read-StrictJsonDocument $file.FullName 'replay-index'
        if ([string]$existing.value.supervisor.operation_attempt_id -ceq
                [string]$Receipt.operation_attempt_id -or
                [string]$existing.value.supervisor.challenge_nonce -ceq
                [string]$Receipt.challenge_nonce) {
            throw 'MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_REPLAY_REJECTED'
        }
    }
}

function Assert-SafeEvidenceId([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 150 -or
            $Value -cnotmatch '^server-version-process-matrix-[a-z0-9][a-z0-9._-]*$' -or
            $Value.Contains('..')) {
        throw 'MCACE_MATRIX_PUBLISH_EVIDENCE_ID_INVALID'
    }
}

function New-Descriptor([string]$Path, [object]$Document) {
    Assert-CanonicalRelativePath $Path 'descriptor-path'
    return [pscustomobject][ordered]@{
        path = $Path
        sha256 = [string]$Document.sha256
        size_bytes = [long]$Document.size_bytes
    }
}

function Assert-OutputRootSafe {
    $root = [IO.Path]::GetPathRoot($outputRootFull)
    if ($outputRootFull.TrimEnd([char[]]@('\','/')) -ceq $root.TrimEnd([char[]]@('\','/'))) {
        throw 'MCACE_MATRIX_PUBLISH_OUTPUT_FILESYSTEM_ROOT_REJECTED'
    }
    $null = Assert-PathChainNoReparse $outputRootFull $false 'output-root'
    if (-not (Test-Path -LiteralPath $outputRootFull)) {
        [void][IO.Directory]::CreateDirectory($outputRootFull)
    }
    $null = Assert-PathChainNoReparse $outputRootFull $true 'output-root'
    if (-not (Test-Path -LiteralPath $outputRootFull -PathType Container)) {
        throw 'MCACE_MATRIX_PUBLISH_OUTPUT_DIRECTORY_REQUIRED'
    }
}

function Read-ExistingIndex([string]$Path) {
    return Read-StrictJsonDocument $Path 'existing-index'
}

function Assert-ImmutableIdentity([object]$Existing, [object]$Expected) {
    $old = $Existing.value
    if ([string]$old.schema -cne $indexSchema -or
            [string]$old.evidence_id -cne [string]$Expected.evidence_id -or
            [string]$old.source_commit -cne [string]$Expected.source_commit -or
            [string]$old.artifact_source_commit -cne [string]$Expected.artifact_source_commit -or
            -not [bool]$old.release_eligible -or
            -not [bool]$old.independent_supervisor_signature_present -or
            [string]$old.ordered_raw_report_set_sha256 -cne [string]$Expected.ordered_raw_report_set_sha256 -or
            [string]$old.release_bundle.manifest_sha256 -cne [string]$Expected.release_bundle.manifest_sha256) {
        throw 'MCACE_MATRIX_PUBLISH_DIVERGENT_IMMUTABLE_EVIDENCE_ID'
    }
    foreach ($role in @('report','binding','commit','raw_manifest','signing_request',
            'supervisor_receipt')) {
        $oldDescriptor = $old.canonical_evidence.$role
        $newDescriptor = $Expected.canonical_evidence.$role
        if ([string]$oldDescriptor.path -cne [string]$newDescriptor.path -or
                [string]$oldDescriptor.sha256 -cne [string]$newDescriptor.sha256 -or
                [long]$oldDescriptor.size_bytes -ne [long]$newDescriptor.size_bytes) {
            throw 'MCACE_MATRIX_PUBLISH_DIVERGENT_IMMUTABLE_EVIDENCE_ID'
        }
    }
    $oldRaw = @($old.canonical_evidence.raw_reports)
    $newRaw = @($Expected.canonical_evidence.raw_reports)
    if ($oldRaw.Count -ne 12 -or $newRaw.Count -ne 12) {
        throw 'MCACE_MATRIX_PUBLISH_DIVERGENT_IMMUTABLE_EVIDENCE_ID'
    }
    for ($index=0; $index -lt 12; $index++) {
        foreach ($name in @('path','sha256','size_bytes')) {
            if ([string]$oldRaw[$index].$name -cne [string]$newRaw[$index].$name) {
                throw 'MCACE_MATRIX_PUBLISH_DIVERGENT_IMMUTABLE_EVIDENCE_ID'
            }
        }
    }
}

function Test-PathBelow([string]$Root, [string]$Candidate) {
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd([char[]]@('\','/')) + [IO.Path]::DirectorySeparatorChar
    $full = [IO.Path]::GetFullPath($Candidate)
    $comparison = if (Test-IsWindowsPlatform) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    return $full.StartsWith($prefix, $comparison)
}

function Remove-TransactionPath([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if (-not (Test-PathBelow $outputRootFull $Path)) {
        throw 'MCACE_MATRIX_PUBLISH_CLEANUP_PATH_ESCAPE'
    }
    $name = Split-Path -Leaf $Path
    if (-not ($name.StartsWith('.matrix-publish-stage-', [StringComparison]::Ordinal) -or
              $name.StartsWith('.matrix-publish-backup-', [StringComparison]::Ordinal))) {
        throw 'MCACE_MATRIX_PUBLISH_CLEANUP_NAME_INVALID'
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer) { [IO.Directory]::Delete($item.FullName, $true) }
    else { [IO.File]::Delete($item.FullName) }
}

if (-not (Test-Commit $ArtifactSourceCommit)) {
    throw 'MCACE_MATRIX_PUBLISH_ARTIFACT_SOURCE_COMMIT_INVALID'
}

$triplet = Assert-ExactTripletPaths
$reportDocument = Read-StrictJsonDocument $triplet.report 'report'
$bindingDocument = Read-StrictJsonDocument $triplet.binding 'binding'
$commitDocument = Read-StrictJsonDocument $triplet.commit 'commit'
$rawManifestDocument = Read-StrictJsonDocument $triplet.raw_manifest 'raw-manifest'
$signingRequestDocument = Read-StrictJsonDocument $triplet.signing_request 'supervisor-signing-request'
$supervisorReceiptDocument = Read-StrictJsonDocument $triplet.supervisor_receipt 'supervisor-receipt'

Assert-Report $reportDocument.value $bindingDocument.value.current.product_jars
Assert-Binding $bindingDocument.value $reportDocument $reportDocument.value
Assert-CommitDocument $commitDocument.value $reportDocument $bindingDocument $reportDocument.value
$rawEvidence = Assert-RawEvidencePackage $rawManifestDocument $reportDocument.value $triplet.directory

$releaseBundle = Read-ReleaseBundle $ReleaseBundleRoot
$productCrossBindings = Assert-CrossBinding $bindingDocument.value.current.product_jars $releaseBundle
$caseRuntimeCommitment = Get-CaseRuntimeCommitments $reportDocument.value $rawEvidence
$releaseArtifactCommitment = Get-ReleaseArtifactCommitment $releaseBundle
$matrixProductCommitment = Get-MatrixProductCommitment $productCrossBindings
$supervisorTrustRoot = Read-MatrixSupervisorTrustRoot $triplet.directory
if ([string]$reportDocument.value.release_source_commit -cne [string]$releaseBundle.source_commit -or
        [string]$reportDocument.value.artifact_source_commit -cne [string]$releaseBundle.artifact_source_commit -or
        [string]$reportDocument.value.release_bundle_manifest_sha256 -cne [string]$releaseBundle.manifest_sha256 -or
        [string]$reportDocument.value.release_bundle_artifact_set_sha256 -cne [string]$releaseArtifactCommitment.sha256 -or
        [string]$reportDocument.value.matrix_product_jar_set_sha256 -cne [string]$matrixProductCommitment.sha256 -or
        [string]$reportDocument.value.case_runtime_commitment_sha256 -cne [string]$caseRuntimeCommitment.sha256 -or
        [string]$reportDocument.value.supervisor_trust_root_sha256 -cne [string]$supervisorTrustRoot.document.sha256 -or
        [string]$reportDocument.value.supervisor_signer_key_id -cne [string]$supervisorTrustRoot.value.key_id) {
    throw 'MCACE_MATRIX_PUBLISH_REPORT_EXTERNAL_BINDING_INVALID'
}
$signingRequest = Assert-SupervisorSigningRequest $signingRequestDocument `
    $reportDocument $bindingDocument $rawManifestDocument $reportDocument.value `
    $releaseBundle $caseRuntimeCommitment $releaseArtifactCommitment `
    $matrixProductCommitment $supervisorTrustRoot
$supervisorReceipt = Assert-SupervisorReceipt $supervisorReceiptDocument `
    $signingRequest $supervisorTrustRoot
if ([string]$commitDocument.value.supervisor_signing_request_sha256 -cne
        [string]$signingRequestDocument.sha256 -or
        [long]$commitDocument.value.supervisor_signing_request_bytes -ne
            [long]$signingRequestDocument.size_bytes -or
        [string]$commitDocument.value.supervisor_receipt_sha256 -cne
            [string]$supervisorReceiptDocument.sha256 -or
        [long]$commitDocument.value.supervisor_receipt_bytes -ne
            [long]$supervisorReceiptDocument.size_bytes) {
    throw 'MCACE_MATRIX_PUBLISH_COMMIT_SUPERVISOR_DOCUMENT_BINDING_INVALID'
}

$generatedTime = ConvertTo-EvidenceTime $reportDocument.value.generated_at 'report.generated_at'
if ([string]::IsNullOrWhiteSpace($EvidenceId)) {
    $timeToken = $generatedTime.ToString('yyyyMMddTHHmmssfffffffZ', [Globalization.CultureInfo]::InvariantCulture)
    $EvidenceId = "server-version-process-matrix-$timeToken-$($reportDocument.sha256.Substring(0,12))"
}
Assert-SafeEvidenceId $EvidenceId
Assert-NoPublishedSupervisorReplay $supervisorReceipt.value $EvidenceId

$nativePrefix = "$matrixDirectoryName/$EvidenceId"
$index = [pscustomobject][ordered]@{
    schema = $indexSchema
    evidence_id = $EvidenceId
    generated_at = $generatedTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    source_mode = 'EXECUTED'
    source_commit = $releaseBundle.source_commit
    artifact_source_commit = $ArtifactSourceCommit
    product_version = $productVersion
    target_versions = @($targetVersions)
    expected_case_count = 12
    observed_case_count = 12
    all_cases_passed = $true
    cleanup_all_zero = $true
    evidence_class = 'EXECUTED_EXTERNALLY_SUPERVISED_RELEASE_EVIDENCE'
    independent_supervisor_signature_required = $true
    independent_supervisor_signature_present = $true
    release_eligible = $true
    release_bundle = [pscustomobject][ordered]@{
        schema = $releaseBundle.schema
        source_commit = $releaseBundle.source_commit
        artifact_source_commit = $releaseBundle.artifact_source_commit
        product_version = $releaseBundle.product_version
        manifest_sha256 = $releaseBundle.manifest_sha256
        manifest_size_bytes = $releaseBundle.manifest_size_bytes
        sha256sums_sha256 = $releaseBundle.sha256sums_sha256
        sha256sums_size_bytes = $releaseBundle.sha256sums_size_bytes
        artifacts = @($releaseBundle.artifact_list)
    }
    matrix_product_jars = @($productCrossBindings)
    ordered_raw_report_set_sha256 = [string]$rawEvidence.ordered_sha256
    supervisor = [pscustomobject][ordered]@{
        trust_root_schema = $trustRootSchema
        trust_root_sha256 = [string]$supervisorTrustRoot.document.sha256
        signer_key_id = [string]$supervisorTrustRoot.value.key_id
        signature_algorithm = 'RSA_PKCS1_SHA256'
        operation_attempt_id = [string]$supervisorReceipt.value.operation_attempt_id
        challenge_nonce = [string]$supervisorReceipt.value.challenge_nonce
        challenge_issued_at = [string]$supervisorReceipt.value.challenge_issued_at
        signed_at = [string]$supervisorReceipt.value.signed_at
        expires_at = [string]$supervisorReceipt.value.expires_at
        case_runtime_commitment_sha256 = [string]$caseRuntimeCommitment.sha256
        process_identity_count = [int]$caseRuntimeCommitment.process_count
        release_bundle_artifact_set_sha256 = [string]$releaseArtifactCommitment.sha256
        matrix_product_jar_set_sha256 = [string]$matrixProductCommitment.sha256
        supervisor_independent = $true
        test_fixture = $false
    }
    canonical_evidence = [pscustomobject][ordered]@{
        report = New-Descriptor "$nativePrefix/report.json" $reportDocument
        binding = New-Descriptor "$nativePrefix/binding.json" $bindingDocument
        commit = New-Descriptor "$nativePrefix/commit.json" $commitDocument
        raw_manifest = New-Descriptor "$nativePrefix/raw-manifest.json" $rawManifestDocument
        signing_request = New-Descriptor "$nativePrefix/supervisor-signing-request.json" $signingRequestDocument
        supervisor_receipt = New-Descriptor "$nativePrefix/supervisor-receipt.json" $supervisorReceiptDocument
        raw_reports = @($rawEvidence.reports | ForEach-Object {
            $ordinal = [int]$_.ordinal - 1
            New-Descriptor "$nativePrefix/$($_.path)" @($rawEvidence.documents)[$ordinal]
        })
    }
}
Assert-NoSecretFieldsOrAbsoluteStrings $index 'index'

Assert-OutputRootSafe
$gateRoot = Join-Path $outputRootFull $matrixDirectoryName
if (-not (Test-Path -LiteralPath $gateRoot)) { [void][IO.Directory]::CreateDirectory($gateRoot) }
$null = Assert-PathChainNoReparse $gateRoot $true 'gate-root'
$finalDirectory = Join-Path $gateRoot $EvidenceId
$finalIndex = Join-Path $outputRootFull ($EvidenceId + '.json')
$directoryExists = Test-Path -LiteralPath $finalDirectory
$indexExists = Test-Path -LiteralPath $finalIndex
if ($directoryExists -xor $indexExists) {
    throw 'MCACE_MATRIX_PUBLISH_DESTINATION_PARTIAL_STATE_REJECTED'
}
if ($directoryExists) {
    if (-not $Force) { throw 'MCACE_MATRIX_PUBLISH_DESTINATION_EXISTS' }
    $null = Assert-PathChainNoReparse $finalDirectory $true 'existing-directory'
    $null = Assert-PathChainNoReparse $finalIndex $true 'existing-index'
    Assert-ImmutableIdentity (Read-ExistingIndex $finalIndex) $index
}

$transactionId = [Guid]::NewGuid().ToString('N')
$stagingRoot = Join-Path $outputRootFull ('.matrix-publish-stage-' + $transactionId)
$stagingDirectory = Join-Path $stagingRoot 'evidence'
$stagingIndex = Join-Path $stagingRoot 'index.json'
$backupDirectory = Join-Path $outputRootFull ('.matrix-publish-backup-directory-' + $transactionId)
$backupIndex = Join-Path $outputRootFull ('.matrix-publish-backup-index-' + $transactionId)
$backedUpDirectory = $false
$backedUpIndex = $false
$installedDirectory = $false
$installedIndex = $false
$transactionCommitted = $false

try {
    [void][IO.Directory]::CreateDirectory($stagingDirectory)
    [void][IO.Directory]::CreateDirectory((Join-Path $stagingDirectory 'raw'))
    $documents = [ordered]@{
        'report.json' = $reportDocument
        'binding.json' = $bindingDocument
        'commit.json' = $commitDocument
        'raw-manifest.json' = $rawManifestDocument
        'supervisor-signing-request.json' = $signingRequestDocument
        'supervisor-receipt.json' = $supervisorReceiptDocument
    }
    foreach ($pair in $documents.GetEnumerator()) {
        [IO.File]::WriteAllBytes(
            (Join-Path $stagingDirectory ([string]$pair.Key)),
            [byte[]]$pair.Value.bytes)
    }
    for ($rawIndex=0; $rawIndex -lt 12; $rawIndex++) {
        $rawDescriptor = @($rawEvidence.reports)[$rawIndex]
        $rawDocument = @($rawEvidence.documents)[$rawIndex]
        [IO.File]::WriteAllBytes(
            (Join-Path $stagingDirectory (([string]$rawDescriptor.path).Replace('/','\'))),
            [byte[]]$rawDocument.bytes)
    }
    $indexBytes = $utf8NoBom.GetBytes(($index | ConvertTo-Json -Depth 20 -Compress) + "`n")
    [IO.File]::WriteAllBytes($stagingIndex, $indexBytes)

    foreach ($role in @('report','binding','commit','signing_request','supervisor_receipt')) {
        $descriptor = $index.canonical_evidence.$role
        $fileName = switch ($role) {
            'signing_request' { 'supervisor-signing-request.json' }
            'supervisor_receipt' { 'supervisor-receipt.json' }
            default { "$role.json" }
        }
        $staged = Join-Path $stagingDirectory $fileName
        $bytes = [IO.File]::ReadAllBytes($staged)
        if ([long]$bytes.Length -ne [long]$descriptor.size_bytes -or
                (Get-BytesSha256 $bytes) -cne [string]$descriptor.sha256) {
            throw "MCACE_MATRIX_PUBLISH_STAGING_DESCRIPTOR_INVALID|$role"
        }
    }
    $null = ConvertFrom-StrictJson ($utf8Strict.GetString([IO.File]::ReadAllBytes($stagingIndex))) 'staging-index'

    if ($directoryExists) {
        [IO.Directory]::Move($finalDirectory, $backupDirectory)
        $backedUpDirectory = $true
        [IO.File]::Move($finalIndex, $backupIndex)
        $backedUpIndex = $true
    }
    [IO.Directory]::Move($stagingDirectory, $finalDirectory)
    $installedDirectory = $true
    [IO.File]::Move($stagingIndex, $finalIndex)
    $installedIndex = $true

    $publishedEntries = @(Get-ChildItem -LiteralPath $finalDirectory -Force -ErrorAction Stop)
    if ($publishedEntries.Count -ne 7 -or
            ((@($publishedEntries.Name | Sort-Object) -join '|') -cne
                'binding.json|commit.json|raw|raw-manifest.json|report.json|supervisor-receipt.json|supervisor-signing-request.json')) {
        throw 'MCACE_MATRIX_PUBLISH_FINAL_PACKAGE_INVALID'
    }
    $publishedRawManifest = Read-LockedFileBytes (Join-Path $finalDirectory 'raw-manifest.json') `
        3 $maximumJsonBytes 'published-raw-manifest'
    if ($publishedRawManifest.sha256 -cne [string]$index.canonical_evidence.raw_manifest.sha256 -or
            $publishedRawManifest.size_bytes -ne [long]$index.canonical_evidence.raw_manifest.size_bytes) {
        throw 'MCACE_MATRIX_PUBLISH_FINAL_RAW_MANIFEST_INVALID'
    }
    foreach ($descriptor in @($index.canonical_evidence.raw_reports)) {
        $publishedRaw = Read-LockedFileBytes `
            (Join-Path $outputRootFull (([string]$descriptor.path).Replace('/','\'))) `
            3 $maximumJsonBytes 'published-raw-report'
        if ($publishedRaw.sha256 -cne [string]$descriptor.sha256 -or
                $publishedRaw.size_bytes -ne [long]$descriptor.size_bytes) {
            throw 'MCACE_MATRIX_PUBLISH_FINAL_RAW_REPORT_INVALID'
        }
    }
    foreach ($role in @('report','binding','commit','signing_request','supervisor_receipt')) {
        $fileName = switch ($role) {
            'signing_request' { 'supervisor-signing-request.json' }
            'supervisor_receipt' { 'supervisor-receipt.json' }
            default { "$role.json" }
        }
        $published = Read-LockedFileBytes (Join-Path $finalDirectory $fileName) `
            3 $maximumJsonBytes "published-$role"
        $descriptor = $index.canonical_evidence.$role
        if ($published.sha256 -cne [string]$descriptor.sha256 -or
                $published.size_bytes -ne [long]$descriptor.size_bytes) {
            throw "MCACE_MATRIX_PUBLISH_FINAL_DESCRIPTOR_INVALID|$role"
        }
    }
    $publishedIndex = Read-StrictJsonDocument $finalIndex 'published-index'
    Assert-ImmutableIdentity $publishedIndex $index
    $transactionCommitted = $true

    if ($backedUpDirectory) { Remove-TransactionPath $backupDirectory }
    if ($backedUpIndex) { Remove-TransactionPath $backupIndex }
} catch {
    $failure = $_
    $rollbackFailures = New-Object 'Collections.Generic.List[string]'
    try {
        if ($installedIndex -and (Test-Path -LiteralPath $finalIndex -PathType Leaf)) {
            [IO.File]::Delete($finalIndex)
        }
    } catch { [void]$rollbackFailures.Add("remove-index:$($_.Exception.Message)") }
    try {
        if ($installedDirectory -and (Test-Path -LiteralPath $finalDirectory -PathType Container)) {
            [IO.Directory]::Delete($finalDirectory, $true)
        }
    } catch { [void]$rollbackFailures.Add("remove-directory:$($_.Exception.Message)") }
    try {
        if ($backedUpIndex -and (Test-Path -LiteralPath $backupIndex -PathType Leaf)) {
            [IO.File]::Move($backupIndex, $finalIndex)
        }
    } catch { [void]$rollbackFailures.Add("restore-index:$($_.Exception.Message)") }
    try {
        if ($backedUpDirectory -and (Test-Path -LiteralPath $backupDirectory -PathType Container)) {
            [IO.Directory]::Move($backupDirectory, $finalDirectory)
        }
    } catch { [void]$rollbackFailures.Add("restore-directory:$($_.Exception.Message)") }
    if ($rollbackFailures.Count -gt 0) {
        throw "MCACE_MATRIX_PUBLISH_ROLLBACK_INCOMPLETE|original=$($failure.Exception.Message)|rollback=$($rollbackFailures -join ' || ')"
    }
    throw $failure
} finally {
    if (Test-Path -LiteralPath $stagingRoot) {
        try { Remove-TransactionPath $stagingRoot } catch { if (-not $transactionCommitted) { throw } }
    }
    if ($transactionCommitted) {
        foreach ($backup in @($backupDirectory,$backupIndex)) {
            if (Test-Path -LiteralPath $backup) {
                try { Remove-TransactionPath $backup } catch { }
            }
        }
    }
}

Write-Output "MCACE_SERVER_VERSION_MATRIX_EVIDENCE_PUBLISHED|index=$EvidenceId.json|directory=$nativePrefix|artifact_source_commit=$ArtifactSourceCommit"
