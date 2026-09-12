[CmdletBinding()]
param(
    [switch]$Execute,
    [switch]$ReportOnly,
    [string]$BundleRoot = (Join-Path $PSScriptRoot '..\build\release-bundle'),
    [string]$ReportPath = (Join-Path $PSScriptRoot '..\build\compatibility-contract\report.json'),
    [string]$ExpectedSourceCommit,
    [string]$ExpectedArtifactSourceCommit,
    [string]$ExpectedReportSha256,
    [ValidateRange(1, 10080)]
    [int]$MaximumReportAgeMinutes = 1440
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Execute -eq $ReportOnly) {
    throw 'MCACE_COMPATIBILITY_CONTRACT_MODE_REQUIRED|select exactly one of -Execute or -ReportOnly'
}

$schema = 'MCACE_VERSION_COMPATIBILITY_CONTRACT_V2'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

$targets = @(
    [ordered]@{
        minecraft_version = '1.21.11'
        protocol = 774
        java_major = 21
        loader = '0.19.3'
        fabric_api = '0.141.6+1.21.11'
        artifact = 'mcace-client-fabric-1.21.11.jar'
        artifact_mode = 'FINAL_REMAP_JAR'
        expected_nested = @(
            'META-INF/jars/mcace-client-common-{VERSION}.jar'
            # The Fabric client embeds the allowlisted client-safe core artifact,
            # whose Gradle classifier is part of the deployable name.  Keeping the
            # classifier in the contract prevents a full server core JAR from being
            # accepted as a client dependency by accident.
            'META-INF/jars/mcace-core-{VERSION}-client-safe.jar'
            'META-INF/jars/mcace-protocol-{VERSION}.jar'
            'META-INF/jars/mcace-sdk-{VERSION}.jar'
            'META-INF/jars/protobuf-java-4.32.1.jar'
        )
    }
    [ordered]@{
        minecraft_version = '26.1.2'
        protocol = 775
        java_major = 25
        loader = '0.19.3'
        fabric_api = '0.155.2+26.1.2'
        artifact = 'mcace-client-fabric-26.1.2.jar'
        artifact_mode = 'FINAL_NAMED_JAR'
        expected_nested = @('META-INF/jars/protobuf-java-4.32.1.jar')
    }
    [ordered]@{
        minecraft_version = '26.2'
        protocol = 776
        java_major = 25
        loader = '0.19.3'
        fabric_api = '0.157.0+26.2'
        artifact = 'mcace-client-fabric-26.2.jar'
        artifact_mode = 'FINAL_NAMED_JAR'
        expected_nested = @('META-INF/jars/protobuf-java-4.32.1.jar')
    }
)

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-Sha256([string]$Path, [string]$Expected, [string]$Label) {
    if ($Expected -cnotmatch '^[0-9a-f]{64}$') {
        throw "MCACE_COMPATIBILITY_SHA256_INVALID|$Label|value=$Expected"
    }
    $actual = Get-Sha256 $Path
    if ($actual -cne $Expected) {
        throw "MCACE_COMPATIBILITY_SHA256_MISMATCH|$Label|expected=$Expected|actual=$actual"
    }
    return $actual
}

function ConvertTo-ReportTimestamp([object]$Value) {
    <#
      ConvertFrom-Json has two materially different timestamp behaviours:
      PowerShell 7 materializes ISO-8601 values as DateTime, while Windows
      PowerShell 5.1 leaves them as strings.  Stringifying a DateTime loses
      its Kind/offset (for example, `...Z` becomes a local-culture value), so
      dispatch on the runtime type before parsing and normalize every accepted
      representation to UTC.  An unspecified DateTime or a string without an
      explicit offset is ambiguous and therefore rejected fail-closed.
    #>
    try {
        if ($null -eq $Value) {
            throw 'timestamp is null'
        }
        if ($Value -is [DateTimeOffset]) {
            return ([DateTimeOffset]$Value).ToUniversalTime()
        }
        if ($Value -is [DateTime]) {
            $dateTime = [DateTime]$Value
            if ($dateTime.Kind -eq [DateTimeKind]::Unspecified) {
                throw 'timestamp DateTime kind is unspecified'
            }
            return ([DateTimeOffset]$dateTime).ToUniversalTime()
        }
        if ($Value -isnot [string]) {
            throw 'timestamp value type is unsupported'
        }

        $text = ([string]$Value).Trim()
        # Require the canonical ISO shape and an explicit UTC/offset designator
        # so a host-local culture/time zone can never silently reinterpret it.
        if ($text -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$') {
            throw 'timestamp string shape is invalid'
        }
        $parsed = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse(
                $text,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind,
                [ref]$parsed)) {
            throw 'timestamp string is not parseable'
        }
        return $parsed.ToUniversalTime()
    }
    catch {
        # Do not leak parser/culture details into the release gate.  Every
        # malformed or ambiguous representation maps to the same fail-closed
        # contract marker consumed by CI and ReportOnly callers.
        throw 'MCACE_COMPATIBILITY_REPORT_AGE_INVALID'
    }
}

function Read-Manifest([string]$Path) {
    $values = [ordered]@{}
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $Path) {
        $lineNumber++
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
        $separator = $line.IndexOf('=')
        if ($separator -lt 1) {
            throw "MCACE_COMPATIBILITY_MANIFEST_LINE_INVALID|line=$lineNumber"
        }
        $key = $line.Substring(0, $separator)
        if ($key -cnotmatch '^[a-z0-9_.]+$') {
            throw "MCACE_COMPATIBILITY_MANIFEST_KEY_INVALID|line=$lineNumber|key=$key"
        }
        if ($values.Contains($key)) {
            throw "MCACE_COMPATIBILITY_MANIFEST_DUPLICATE_KEY|line=$lineNumber|key=$key"
        }
        $values[$key] = $line.Substring($separator + 1)
    }
    return [pscustomobject]$values
}

function Assert-ExactPropertySet([object]$Value, [string[]]$Expected, [string]$Label) {
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    if (($actual -join '|') -cne ($wanted -join '|')) {
        throw "MCACE_COMPATIBILITY_PROPERTY_SET_INVALID|$Label|expected=$($wanted -join ',')|actual=$($actual -join ',')"
    }
}

function Get-ArtifactManifestKey([string]$FileName) {
    if (-not $FileName.EndsWith('.jar', [StringComparison]::Ordinal)) {
        throw "MCACE_COMPATIBILITY_ARTIFACT_NAME_INVALID|$FileName"
    }
    return $FileName.Substring(0, $FileName.Length - 4).Replace('-', '_').Replace('.', '_')
}

function Assert-RegularFileNoLinks([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "MCACE_COMPATIBILITY_FILE_REQUIRED|$Label"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "MCACE_COMPATIBILITY_REPARSE_POINT_REJECTED|$Label"
    }
}

function Read-ZipJson([string]$ZipPath, [string]$EntryName) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $matches = @($archive.Entries | Where-Object { $_.FullName -ceq $EntryName })
        if ($matches.Count -ne 1) {
            throw "MCACE_COMPATIBILITY_ZIP_ENTRY_COUNT_INVALID|$EntryName|count=$($matches.Count)"
        }
        $entry = $matches[0]
        if ($entry.Length -le 0 -or $entry.Length -gt 1048576) {
            throw "MCACE_COMPATIBILITY_ZIP_ENTRY_SIZE_INVALID|$EntryName|size=$($entry.Length)"
        }
        $reader = [IO.StreamReader]::new($entry.Open())
        try { return ($reader.ReadToEnd() | ConvertFrom-Json) }
        finally { $reader.Dispose() }
    }
    finally { $archive.Dispose() }
}

function Assert-NestedZipEntries([string]$ZipPath, [string[]]$ExpectedNested) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $counts = @{}
        foreach ($entry in $archive.Entries) {
            $name = [string]$entry.FullName
            if ([string]::IsNullOrWhiteSpace($name) -or $name.Contains('\') -or
                    $name.StartsWith('/', [StringComparison]::Ordinal) -or
                    $name -match '(^|/)\.\.(/|$)') {
                throw "MCACE_COMPATIBILITY_ZIP_ENTRY_NAME_INVALID|$name"
            }
            if ($counts.ContainsKey($name)) {
                throw "MCACE_COMPATIBILITY_ZIP_DUPLICATE_ENTRY|$name"
            }
            $counts[$name] = 1
        }
        # Loom writes an explicit META-INF/jars/ directory entry in the final
        # remap JAR.  The dependency contract is about nested JAR files, not
        # that directory marker, so ignore directory entries here while still
        # validating every file entry and rejecting duplicate names.
        $actualNested = @($counts.Keys | Where-Object {
            $_.StartsWith('META-INF/jars/', [StringComparison]::Ordinal) -and
                -not $_.EndsWith('/', [StringComparison]::Ordinal)
        } | Sort-Object)
        if (($actualNested -join '|') -cne (@($ExpectedNested | Sort-Object) -join '|')) {
            throw 'MCACE_COMPATIBILITY_NESTED_JAR_ENTRY_SET_INVALID'
        }
    }
    finally { $archive.Dispose() }
}

function Assert-TargetArtifact([object]$Target, [object]$Manifest, [string]$Root) {
    $artifactPath = Join-Path $Root $Target.artifact
    Assert-RegularFileNoLinks $artifactPath $Target.artifact
    $propertyPrefix = 'artifact.mcace_client_fabric_' + ($Target.minecraft_version -replace '\.', '_')
    $manifestFile = [string]$Manifest."$propertyPrefix.file"
    $manifestSha = [string]$Manifest."$propertyPrefix.sha256"
    $manifestMinecraftVersion = [string]$Manifest."$propertyPrefix.minecraft_version"
    $manifestBuildId = [string]$Manifest."$propertyPrefix.client_build_id"
    $expectedBuildId = "fabric-$($Target.minecraft_version)-$($Manifest.artifact_source_commit)"
    if ($manifestFile -cne $Target.artifact -or
            $manifestMinecraftVersion -cne $Target.minecraft_version -or
            $manifestBuildId -cne $expectedBuildId) {
        throw "MCACE_COMPATIBILITY_MANIFEST_ARTIFACT_MISMATCH|$($Target.minecraft_version)"
    }
    $artifactSha = Assert-Sha256 $artifactPath $manifestSha $Target.artifact
    $metadata = Read-ZipJson $artifactPath 'fabric.mod.json'
    if ([int]$metadata.schemaVersion -ne 1 -or
            [string]$metadata.id -cne 'mcace' -or
            [string]$metadata.version -cne [string]$Manifest.product_version -or
            [string]$metadata.environment -cne 'client' -or
            @($metadata.entrypoints.client).Count -ne 1 -or
            [string]$metadata.entrypoints.client[0] -cne 'com.ellan.mcace.fabric.MCAceFabricClient' -or
            [string]$metadata.depends.minecraft -cne $Target.minecraft_version -or
            [string]$metadata.depends.'fabric-api' -cne $Target.fabric_api -or
            [string]$metadata.depends.fabricloader -cne ">=$($Target.loader)" -or
            [string]$metadata.custom.'mcace:client_build_id' -cne $expectedBuildId) {
        throw "MCACE_COMPATIBILITY_METADATA_MISMATCH|$($Target.minecraft_version)"
    }
    $javaRequirement = [string]$metadata.depends.java
    if ($javaRequirement -cne ">=$($Target.java_major)") {
        throw "MCACE_COMPATIBILITY_JAVA_REQUIREMENT_MISMATCH|$($Target.minecraft_version)"
    }
    $productVersion = [string]$Manifest.product_version
    if ($productVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') {
        throw 'MCACE_COMPATIBILITY_PRODUCT_VERSION_INVALID'
    }
    $expectedNested = @($Target.expected_nested | ForEach-Object {
        $_ -replace '\{VERSION\}', $productVersion
    })
    $nested = @($metadata.jars | ForEach-Object { [string]$_.file })
    if ((@($nested) -join '|') -cne (@($expectedNested) -join '|')) {
        throw "MCACE_COMPATIBILITY_NESTED_JAR_CONTRACT_MISMATCH|$($Target.minecraft_version)"
    }
    Assert-NestedZipEntries $artifactPath $expectedNested
    [ordered]@{
        minecraft_version = $Target.minecraft_version
        protocol = [int]$Target.protocol
        java_major = [int]$Target.java_major
        artifact_mode = $Target.artifact_mode
        artifact = $Target.artifact
        sha256 = $artifactSha
        nested_jar_count = @($nested).Count
        passed = $true
    }
}

function Invoke-Execute {
    $root = [IO.Path]::GetFullPath($BundleRoot)
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw 'MCACE_COMPATIBILITY_RELEASE_BUNDLE_REQUIRED|bundle root is missing'
    }
    $rootItem = Get-Item -LiteralPath $root -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'MCACE_COMPATIBILITY_REPARSE_POINT_REJECTED|bundle-root'
    }
    $manifestPath = Join-Path $root 'release-manifest.properties'
    $sumsPath = Join-Path $root 'SHA256SUMS'
    Assert-RegularFileNoLinks $manifestPath 'release-manifest.properties'
    Assert-RegularFileNoLinks $sumsPath 'SHA256SUMS'
    $manifest = Read-Manifest $manifestPath
    $jarNames = @($targets | ForEach-Object { $_.artifact }) + @(
        'mcace-server-velocity.jar',
        'mcace-server-bungeecord.jar',
        'mcace-server-paper.jar'
    )
    $manifestProperties = @(
        'schema', 'bundle_profile', 'release_identity', 'deployable_count',
        'bundle_entry_count', 'product_version', 'source_commit',
        'artifact_source_commit', 'root_java_version',
        'root_java_specification_version', 'root_gradle_version',
        'modern_java_version', 'modern_java_specification_version',
        'modern_gradle_version'
    )
    foreach ($jarName in $jarNames) {
        $key = Get-ArtifactManifestKey $jarName
        $manifestProperties += "artifact.$key.file"
        $manifestProperties += "artifact.$key.sha256"
        if ($jarName.StartsWith('mcace-client-fabric-', [StringComparison]::Ordinal)) {
            $manifestProperties += "artifact.$key.minecraft_version"
            $manifestProperties += "artifact.$key.client_build_id"
        }
    }
    Assert-ExactPropertySet $manifest $manifestProperties 'release-manifest'
    if ([string]$manifest.schema -cne 'MCACE_RELEASE_BUNDLE_V4' -or
            [string]$manifest.bundle_profile -cne 'RELEASE' -or
            [string]$manifest.release_identity -cne 'true' -or
            [string]$manifest.product_version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
            [int]$manifest.deployable_count -ne 6 -or
            [int]$manifest.bundle_entry_count -ne 8 -or
            [string]$manifest.root_java_version -cnotmatch '^21(?:\.|$)' -or
            [string]$manifest.root_java_specification_version -cne '21' -or
            [string]$manifest.root_gradle_version -cne '9.6.1' -or
            [string]$manifest.modern_java_version -cnotmatch '^25(?:\.|$)' -or
            [string]$manifest.modern_java_specification_version -cne '25' -or
            [string]$manifest.modern_gradle_version -cne '9.6.1') {
        throw 'MCACE_COMPATIBILITY_RELEASE_MANIFEST_CONTRACT_INVALID'
    }
    if ([string]$manifest.source_commit -notmatch '^[0-9a-f]{40}$') {
        throw 'MCACE_COMPATIBILITY_SOURCE_COMMIT_INVALID'
    }
    if ([string]$manifest.artifact_source_commit -notmatch '^[0-9a-f]{40}$') {
        throw 'MCACE_COMPATIBILITY_ARTIFACT_SOURCE_COMMIT_INVALID'
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSourceCommit) -and
            [string]$manifest.source_commit -cne $ExpectedSourceCommit.Trim().ToLowerInvariant()) {
        throw "MCACE_COMPATIBILITY_SOURCE_COMMIT_MISMATCH|expected=$($ExpectedSourceCommit.Trim().ToLowerInvariant())|actual=$($manifest.source_commit)"
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedArtifactSourceCommit) -and
            [string]$manifest.artifact_source_commit -cne
                $ExpectedArtifactSourceCommit.Trim().ToLowerInvariant()) {
        throw "MCACE_COMPATIBILITY_ARTIFACT_SOURCE_COMMIT_MISMATCH|expected=$($ExpectedArtifactSourceCommit.Trim().ToLowerInvariant())|actual=$($manifest.artifact_source_commit)"
    }
    $sumLines = @(Get-Content -LiteralPath $sumsPath)
    if (@($sumLines).Count -ne 6) { throw 'MCACE_COMPATIBILITY_SHA256SUMS_COUNT_INVALID' }
    $seenSumNames = @{}
    foreach ($line in $sumLines) {
        if ($line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*\.jar)$') {
            throw "MCACE_COMPATIBILITY_SHA256SUMS_ENTRY_INVALID|$line"
        }
        $hash = $Matches[1]
        $name = $Matches[2]
        if ($name -notin $jarNames) {
            throw "MCACE_COMPATIBILITY_SHA256SUMS_ENTRY_INVALID|$line"
        }
        if ($seenSumNames.ContainsKey($name)) {
            throw "MCACE_COMPATIBILITY_SHA256SUMS_DUPLICATE_FILE|$name"
        }
        $seenSumNames[$name] = $true
        Assert-RegularFileNoLinks (Join-Path $root $name) $name
        Assert-Sha256 (Join-Path $root $name) $hash $name | Out-Null

        $key = Get-ArtifactManifestKey $name
        if ([string]$manifest."artifact.$key.file" -cne $name -or
                [string]$manifest."artifact.$key.sha256" -cne $hash) {
            throw "MCACE_COMPATIBILITY_MANIFEST_CHECKSUM_MISMATCH|$name"
        }
    }
    if ((@($seenSumNames.Keys | Sort-Object) -join '|') -cne (@($jarNames | Sort-Object) -join '|')) {
        throw 'MCACE_COMPATIBILITY_SHA256SUMS_FILE_SET_INVALID'
    }
    $results = @($targets | ForEach-Object { Assert-TargetArtifact $_ $manifest $root })
    $topLevel = @([IO.Directory]::EnumerateFileSystemEntries($root) | ForEach-Object {
        [IO.Path]::GetFileName($_)
    } | Sort-Object)
    $expectedTopLevel = @($jarNames + 'release-manifest.properties' + 'SHA256SUMS' | Sort-Object)
    if ((@($topLevel) -join '|') -cne (@($expectedTopLevel) -join '|')) {
        throw 'MCACE_COMPATIBILITY_TOP_LEVEL_ENTRY_SET_INVALID'
    }
    $report = [ordered]@{
        schema = $schema
        generated_at = (Get-Date).ToUniversalTime().ToString('o')
        source_commit = [string]$manifest.source_commit
        artifact_source_commit = [string]$manifest.artifact_source_commit
        target_count = @($results).Count
        exact_bundle_entry_count = [int]$manifest.bundle_entry_count
        unsupported_versions_are_fail_closed = $true
        unsupported_examples = @('1.21.1', '1.21.10', '26.1', '26.3')
        targets = $results
        passed = $true
    }
    $outRoot = Split-Path -Parent ([IO.Path]::GetFullPath($ReportPath))
    [IO.Directory]::CreateDirectory($outRoot) | Out-Null
    $staging = Join-Path $outRoot ('.staging-' + [Guid]::NewGuid().ToString('N'))
    $stagingFile = Join-Path $staging 'report.json'
    [IO.Directory]::CreateDirectory($staging) | Out-Null
    try {
        $json = $report | ConvertTo-Json -Depth 8
        [IO.File]::WriteAllText($stagingFile, $json, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $stagingFile -Destination ([IO.Path]::GetFullPath($ReportPath)) -Force
    }
    finally { if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue } }
    Write-Output 'MCACE_VERSION_COMPATIBILITY_EXECUTE_PASS'
}

function Invoke-ReportOnly {
    Assert-RegularFileNoLinks ([IO.Path]::GetFullPath($ReportPath)) 'report'
    if ($ExpectedReportSha256) { Assert-Sha256 $ReportPath $ExpectedReportSha256 'report' | Out-Null }
    $report = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json
    Assert-ExactPropertySet $report @(
        'schema', 'generated_at', 'source_commit', 'artifact_source_commit',
        'target_count', 'exact_bundle_entry_count',
        'unsupported_versions_are_fail_closed', 'unsupported_examples', 'targets', 'passed'
    ) 'report'
    if ([string]$report.schema -cne $schema -or
            $report.passed -ne $true -or
            [string]$report.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
            [string]$report.artifact_source_commit -cnotmatch '^[0-9a-f]{40}$' -or
            [int]$report.target_count -ne 3 -or
            [int]$report.exact_bundle_entry_count -ne 8 -or
            $report.unsupported_versions_are_fail_closed -ne $true -or
            @($report.targets).Count -ne 3 -or
            @($report.targets | Where-Object { $_.passed -ne $true }).Count -ne 0) {
        throw 'MCACE_COMPATIBILITY_REPORT_CONTRACT_INVALID'
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSourceCommit) -and
            [string]$report.source_commit -cne $ExpectedSourceCommit.Trim().ToLowerInvariant()) {
        throw 'MCACE_COMPATIBILITY_REPORT_SOURCE_COMMIT_MISMATCH'
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedArtifactSourceCommit) -and
            [string]$report.artifact_source_commit -cne
                $ExpectedArtifactSourceCommit.Trim().ToLowerInvariant()) {
        throw 'MCACE_COMPATIBILITY_REPORT_ARTIFACT_SOURCE_COMMIT_MISMATCH'
    }
    if ((@($report.unsupported_examples | ForEach-Object { [string]$_ }) -join '|') -cne
            '1.21.1|1.21.10|26.1|26.3') {
        throw 'MCACE_COMPATIBILITY_REPORT_UNSUPPORTED_EXAMPLES_INVALID'
    }
    $expectedVersions = @('1.21.11', '26.1.2', '26.2')
    for ($i = 0; $i -lt 3; $i++) {
        $target = $report.targets[$i]
        Assert-ExactPropertySet $target @(
            'minecraft_version', 'protocol', 'java_major', 'artifact_mode',
            'artifact', 'sha256', 'nested_jar_count', 'passed'
        ) "report-target-$i"
        if ([string]$target.minecraft_version -cne $expectedVersions[$i] -or
                [string]$target.sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw "MCACE_COMPATIBILITY_REPORT_TARGET_INVALID|index=$i"
        }
    }
    # ConvertFrom-Json may return DateTime, DateTimeOffset, or string depending
    # on PowerShell/.NET version.  The helper preserves the instant and returns
    # a UTC DateTimeOffset instead of reparsing a localized DateTime string.
    $generated = (ConvertTo-ReportTimestamp $report.generated_at).ToUniversalTime()
    $now = [DateTimeOffset]::UtcNow
    if ($generated -lt $now.AddMinutes(-$MaximumReportAgeMinutes) -or $generated -gt $now.AddMinutes(1)) {
        throw 'MCACE_COMPATIBILITY_REPORT_AGE_INVALID'
    }
    Write-Output 'MCACE_VERSION_COMPATIBILITY_REPORTONLY_PASS'
}

if ($Execute) { Invoke-Execute }
else { Invoke-ReportOnly }
