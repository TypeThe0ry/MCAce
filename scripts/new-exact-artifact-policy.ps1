[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')]
    [string]$EntryId,
    [ValidateSet('MOD', 'RESOURCE_PACK', 'SHADER_PACK', 'CONFIG')]
    [string]$ArtifactType = 'RESOURCE_PACK',
    [Parameter(Mandatory = $true)]
    [ValidateSet('ExactSha256', 'ContentRoot')]
    [string]$MatchType,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Review aid only: hashes local bytes, emits a disabled catalog entry, and never enables or
# publishes a rule.  An administrator must review the bytes and explicitly change the selection.
$script:MaxFiles = 16384
$script:MaxPathChars = 512

function Assert-RegularNoReparse([System.IO.FileSystemInfo]$Item, [string]$Label) {
    if ($null -eq $Item -or ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must not be a reparse point"
    }
}

function Get-RegularFiles([string]$Root) {
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($Root)
    $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force)) {
            Assert-RegularNoReparse $child 'artifact entry'
            if ($child.PSIsContainer) { $pending.Push($child.FullName) }
            elseif ($child -is [System.IO.FileInfo]) { $files.Add($child) }
        }
        if ($files.Count -gt $script:MaxFiles) { throw 'artifact file count exceeds the integrity budget' }
    }
    return @($files | Sort-Object @{ Expression = { $_.FullName }; Ascending = $true })
}

function Get-HashHex([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Convert-FromHexCompat([string]$Hex) {
    if (($Hex.Length % 2) -ne 0 -or $Hex -notmatch '^[0-9A-Fa-f]*$') {
        throw 'hex input is malformed'
    }
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16)
    }
    return $bytes
}

function Convert-ToHexCompat([byte[]]$Bytes) {
    $builder = New-Object System.Text.StringBuilder ($Bytes.Length * 2)
    foreach ($byte in $Bytes) { [void]$builder.Append($byte.ToString('x2')) }
    return $builder.ToString()
}

function Get-RelativePathCompat([string]$Root, [string]$Path) {
    # Windows worker validation still runs under inbox Windows PowerShell 5.1,
    # whose .NET Framework Path type does not expose GetRelativePath. Keep the
    # canonical .NET Core path on pwsh, but use a URI-relative fallback there.
    $method = [IO.Path].GetMethod('GetRelativePath', [Type[]]@([string], [string]))
    if ($null -ne $method) {
        return [IO.Path]::GetRelativePath($Root, $Path)
    }

    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $pathFull = [IO.Path]::GetFullPath($Path)
    $rootUri = New-Object System.Uri($rootFull)
    $pathUri = New-Object System.Uri($pathFull)
    return [Uri]::UnescapeDataString($rootUri.MakeRelativeUri($pathUri).ToString()).Replace('/', '\')
}

function Get-DirectoryContentRoot([string]$Root) {
    $files = @(Get-RegularFiles $Root)
    if ($files.Count -eq 0) { throw 'content-root artifact directory is empty' }
    $entries = foreach ($file in $files) {
        $relative = (Get-RelativePathCompat $Root $file.FullName).Replace('\', '/')
        if ($relative.Length -eq 0 -or $relative.Length -gt $script:MaxPathChars -or
                $relative.StartsWith('/') -or $relative.Contains('//')) { throw 'artifact relative path is outside bounds' }
        foreach ($segment in $relative.Split('/')) {
            if ($segment.Length -eq 0 -or $segment -eq '.' -or $segment -eq '..' -or
                    $segment.IndexOfAny([char[]]@('/', '\', ':')) -ge 0 -or
                    @($segment.ToCharArray() | Where-Object { [char]::IsControl($_) }).Count -gt 0) {
                throw 'artifact relative path is unsafe'
            }
        }
        [pscustomobject]@{ Path = $relative; Size = [long]$file.Length; Hash = (Get-HashHex $file.FullName) }
    }
    $orderedList = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $entries) { $orderedList.Add($entry) }
    $orderedList.Sort([System.Collections.Generic.Comparer[object]]::Create({
        param($left, $right)
        [StringComparer]::Ordinal.Compare([string]$left.Path, [string]$right.Path)
    }))
    $ordered = $orderedList.ToArray()
    $digest = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.MemoryStream]::new()
    try {
        $stream.Write([Text.Encoding]::UTF8.GetBytes("mcace-manifest-v1`0"), 0, 18)
        foreach ($entry in $ordered) {
            $pathBytes = [Text.Encoding]::UTF8.GetBytes($entry.Path)
            $pathLength = [BitConverter]::GetBytes([int]$pathBytes.Length)
            $sizeBytes = [BitConverter]::GetBytes([long]$entry.Size)
            if ([BitConverter]::IsLittleEndian) {
                [Array]::Reverse($pathLength)
                [Array]::Reverse($sizeBytes)
            }
            $stream.Write($pathLength, 0, $pathLength.Length)
            $stream.Write($pathBytes, 0, $pathBytes.Length)
            $stream.Write($sizeBytes, 0, $sizeBytes.Length)
            $hashBytes = Convert-FromHexCompat $entry.Hash
            $stream.Write($hashBytes, 0, $hashBytes.Length)
        }
        return Convert-ToHexCompat ($digest.ComputeHash($stream.ToArray()))
    } finally {
        $stream.Dispose(); $digest.Dispose()
    }
}

function Quote-TextProto([string]$Value) {
    return '"' + $Value.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n') + '"'
}

function Write-Utf8Atomic([string]$Path, [string]$Text) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.Path]::IsPathFullyQualified($full)) { throw 'OutputPath must be absolute' }
    $parent = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'OutputPath parent does not exist' }
    if (Test-Path -LiteralPath $full) { Assert-RegularNoReparse (Get-Item -LiteralPath $full) 'OutputPath' }
    $temporary = Join-Path $parent ('.mcace-policy-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllText($temporary, $Text, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $full -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

$item = Get-Item -LiteralPath $ArtifactPath -ErrorAction Stop
Assert-RegularNoReparse $item 'ArtifactPath'
$isDirectory = $item.PSIsContainer
if ($MatchType -eq 'ContentRoot' -and (-not $isDirectory -or $ArtifactType -notin @('RESOURCE_PACK', 'SHADER_PACK'))) {
    throw 'ContentRoot requires a regular resource-pack or shader-pack directory'
}
if ($MatchType -eq 'ExactSha256' -and $isDirectory) { throw 'ExactSha256 requires a regular artifact file' }

$hash = if ($MatchType -eq 'ContentRoot') { Get-DirectoryContentRoot $item.FullName } else { Get-HashHex $item.FullName }
$selectorType = "DETECTION_ARTIFACT_$ArtifactType"
$selectorMatch = if ($MatchType -eq 'ContentRoot') { 'DETECTION_MATCH_CONTENT_ROOT' } else { 'DETECTION_MATCH_EXACT_SHA256' }
$category = switch ($ArtifactType) {
    'MOD' { 'CHEAT_MOD' }
    'RESOURCE_PACK' { 'XRAY_RESOURCE_PACK' }
    'SHADER_PACK' { 'XRAY_RESOURCE_PACK' }
    'CONFIG' { 'SUSPICIOUS_CONFIG' }
}
$hashField = if ($MatchType -eq 'ContentRoot') { "  content_root_sha256_hex: `"$hash`"`n" } else { "  sha256_hex: `"$hash`"`n" }
$summary = if ($MatchType -eq 'ContentRoot') {
    'Local reviewed directory content-root; generated from canonical mcace-manifest-v1 entries.'
} else {
    'Local reviewed artifact SHA-256; bytes are not embedded and selection is disabled.'
}
$text = @"
# Generated by scripts/new-exact-artifact-policy.ps1.
# Review the artifact and policy before enabling the explicit catalog selection.
schema_version: 1
version: "artifact-review-$EntryId-v1"
rollout_stage: "OBSERVE"
validity_seconds: 86400

catalog_entries {
  entry_id: $(Quote-TextProto $EntryId)
  category: $category
  selector {
    artifact_type: $selectorType
    match_type: $selectorMatch
  }
$hashField  confidence: DETECTION_CONFIDENCE_CONFIRMED
  suggested_action: DISPOSITION_WARN
  player_message_key: "mcace.catalog.review"
  operator_reason: "Exact artifact evidence is available for independent review."
  false_positive_notes: "Do not enable without confirming provenance, scope, and false-positive handling."
  source_id: "local-reviewed-artifact"
  source_summary: $(Quote-TextProto $summary)
  default_enabled: false
}

# Explicit selection is intentionally disabled. Set enabled=true and choose a final_action only
# after review; publishing the generated file as-is has no enforcement effect.
catalog_selections { entry_id: $(Quote-TextProto $EntryId) enabled: false }
"@
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) { Write-Utf8Atomic $OutputPath $text; Write-Verbose "wrote $OutputPath" }
Write-Output $text.TrimStart()
